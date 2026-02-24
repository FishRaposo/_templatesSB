"""
Webhook Routes - Stripe and Other Integrations
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
import stripe

from app.dependencies import get_db
from app.services.billing_service import BillingService
from app.config import settings


router = APIRouter()
logger = logging.getLogger(__name__)


# ============================================================================
# Stripe Webhooks
# ============================================================================

@router.post("/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="Stripe-Signature"),
    db = Depends(get_db),
):
    """Handle Stripe webhook events."""
    if not settings.services.stripe_webhook_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhooks not configured",
        )
    
    # Get request body
    payload = await request.body()
    
    # Verify webhook signature
    try:
        event = stripe.Webhook.construct_event(
            payload,
            stripe_signature,
            settings.services.stripe_webhook_secret.get_secret_value(),
        )
    except ValueError as e:
        logger.error(f"Invalid stripe payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid stripe signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    # Process event
    billing_service = BillingService(db)
    
    try:
        event_type = event["type"]
        event_data = event["data"]["object"]
        
        logger.info(f"Processing Stripe event: {event_type}")
        
        # Subscription events
        if event_type == "customer.subscription.created":
            await handle_subscription_created(billing_service, event_data)
        
        elif event_type == "customer.subscription.updated":
            await handle_subscription_updated(billing_service, event_data)
        
        elif event_type == "customer.subscription.deleted":
            await handle_subscription_deleted(billing_service, event_data)
        
        # Payment events
        elif event_type == "invoice.paid":
            await handle_invoice_paid(billing_service, event_data)
        
        elif event_type == "invoice.payment_failed":
            await handle_payment_failed(billing_service, event_data)
        
        # Checkout events
        elif event_type == "checkout.session.completed":
            await handle_checkout_completed(billing_service, event_data)
        
        else:
            logger.info(f"Unhandled event type: {event_type}")
        
        return {"received": True}
    
    except Exception as e:
        logger.exception(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


# ============================================================================
# Stripe Event Handlers
# ============================================================================

async def handle_subscription_created(
    billing_service: BillingService,
    data: Dict[str, Any],
):
    """Handle subscription.created event."""
    subscription_id = data["id"]
    customer_id = data["customer"]
    status = data["status"]
    
    # Get tier from metadata
    tier = data.get("metadata", {}).get("tier", "starter")
    org_id = data.get("metadata", {}).get("organization_id")
    
    if org_id:
        await billing_service.create_or_update_subscription(
            organization_id=int(org_id),
            stripe_subscription_id=subscription_id,
            stripe_price_id=data["items"]["data"][0]["price"]["id"],
            status=status,
            tier=tier,
            current_period_start=data["current_period_start"],
            current_period_end=data["current_period_end"],
        )
        
        logger.info(f"Created subscription for org {org_id}: {subscription_id}")


async def handle_subscription_updated(
    billing_service: BillingService,
    data: Dict[str, Any],
):
    """Handle subscription.updated event."""
    subscription_id = data["id"]
    status = data["status"]
    
    await billing_service.update_subscription_status(
        stripe_subscription_id=subscription_id,
        status=status,
        current_period_start=data.get("current_period_start"),
        current_period_end=data.get("current_period_end"),
        cancel_at_period_end=data.get("cancel_at_period_end", False),
    )
    
    logger.info(f"Updated subscription {subscription_id}: status={status}")


async def handle_subscription_deleted(
    billing_service: BillingService,
    data: Dict[str, Any],
):
    """Handle subscription.deleted event."""
    subscription_id = data["id"]
    
    await billing_service.cancel_subscription(
        stripe_subscription_id=subscription_id,
    )
    
    logger.info(f"Canceled subscription: {subscription_id}")


async def handle_invoice_paid(
    billing_service: BillingService,
    data: Dict[str, Any],
):
    """Handle invoice.paid event."""
    invoice_id = data["id"]
    subscription_id = data.get("subscription")
    customer_id = data["customer"]
    amount_paid = data["amount_paid"]
    
    if subscription_id:
        # Update subscription status to active
        await billing_service.update_subscription_status(
            stripe_subscription_id=subscription_id,
            status="active",
        )
    
    # Record payment
    await billing_service.record_payment(
        stripe_invoice_id=invoice_id,
        stripe_customer_id=customer_id,
        amount=amount_paid,
        currency=data["currency"],
    )
    
    logger.info(f"Recorded payment for invoice {invoice_id}: {amount_paid}")


async def handle_payment_failed(
    billing_service: BillingService,
    data: Dict[str, Any],
):
    """Handle invoice.payment_failed event."""
    invoice_id = data["id"]
    subscription_id = data.get("subscription")
    customer_id = data["customer"]
    attempt_count = data.get("attempt_count", 1)
    
    if subscription_id:
        # Update subscription status
        await billing_service.update_subscription_status(
            stripe_subscription_id=subscription_id,
            status="past_due",
        )
        
        # Send notification after multiple failures
        if attempt_count >= 3:
            await billing_service.notify_payment_failure(
                stripe_customer_id=customer_id,
                subscription_id=subscription_id,
            )
    
    logger.warning(f"Payment failed for invoice {invoice_id}, attempt {attempt_count}")


async def handle_checkout_completed(
    billing_service: BillingService,
    data: Dict[str, Any],
):
    """Handle checkout.session.completed event."""
    session_id = data["id"]
    customer_id = data["customer"]
    subscription_id = data.get("subscription")
    
    # Get organization from metadata
    org_id = data.get("metadata", {}).get("organization_id")
    
    if org_id and customer_id:
        # Link Stripe customer to organization
        await billing_service.link_stripe_customer(
            organization_id=int(org_id),
            stripe_customer_id=customer_id,
        )
    
    logger.info(f"Checkout completed: session={session_id}, subscription={subscription_id}")


# ============================================================================
# Generic Webhook Endpoint
# ============================================================================

@router.post("/generic/{provider}")
async def generic_webhook(
    provider: str,
    request: Request,
    db = Depends(get_db),
):
    """Generic webhook endpoint for other providers."""
    payload = await request.json()
    
    logger.info(f"Received webhook from {provider}: {payload}")
    
    # Add provider-specific handling here
    if provider == "sendgrid":
        await handle_sendgrid_webhook(payload, db)
    elif provider == "github":
        await handle_github_webhook(payload, db)
    else:
        logger.info(f"Unhandled webhook provider: {provider}")
    
    return {"received": True}


async def handle_sendgrid_webhook(payload: Dict[str, Any], db):
    """Handle SendGrid email events."""
    for event in payload:
        event_type = event.get("event")
        email = event.get("email")
        
        if event_type == "bounce":
            logger.warning(f"Email bounced for: {email}")
            # Mark email as invalid
        elif event_type == "spam_report":
            logger.warning(f"Spam report for: {email}")
            # Handle unsubscribe
        elif event_type == "open":
            logger.info(f"Email opened by: {email}")


async def handle_github_webhook(payload: Dict[str, Any], db):
    """Handle GitHub webhook events."""
    event_type = payload.get("action")
    
    logger.info(f"GitHub event: {event_type}")
    # Add specific handling for GitHub events
