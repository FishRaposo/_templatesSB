"""
Billing API Routes - Stripe Integration
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
import stripe

from app.dependencies import get_db, get_current_user, get_current_org
from app.models import User, Organization, Subscription, SubscriptionTier
from app.schemas.billing import (
    SubscriptionResponse,
    CreateCheckoutRequest,
    CreateCheckoutResponse,
    PortalSessionResponse,
    PriceResponse,
    InvoiceResponse,
    UsageResponse,
)
from app.services.billing_service import BillingService
from app.config import settings


router = APIRouter()

# Initialize Stripe
stripe.api_key = settings.services.stripe_secret_key.get_secret_value() if settings.services.stripe_secret_key else None


# ============================================================================
# Subscription Management
# ============================================================================

@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    org: Organization = Depends(get_current_org),
    db = Depends(get_db),
):
    """Get current subscription details."""
    billing_service = BillingService(db)
    subscription = await billing_service.get_subscription(org.id)
    
    if not subscription:
        # Return free tier defaults
        return SubscriptionResponse(
            tier=SubscriptionTier.FREE,
            status="active",
            seats_limit=5,
            storage_limit_mb=1000,
            api_calls_limit=10000,
        )
    
    return subscription


@router.get("/usage", response_model=UsageResponse)
async def get_usage(
    org: Organization = Depends(get_current_org),
    db = Depends(get_db),
):
    """Get current usage statistics."""
    billing_service = BillingService(db)
    return await billing_service.get_usage(org.id)


# ============================================================================
# Checkout
# ============================================================================

@router.post("/checkout", response_model=CreateCheckoutResponse)
async def create_checkout_session(
    data: CreateCheckoutRequest,
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Create a Stripe checkout session for subscription."""
    if not stripe.api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is not configured",
        )
    
    billing_service = BillingService(db)
    
    # Ensure organization has a Stripe customer
    customer_id = org.stripe_customer_id
    if not customer_id:
        customer = await billing_service.create_stripe_customer(org, user)
        customer_id = customer.id
    
    # Get price ID for the tier
    price_id = billing_service.get_price_id(data.tier)
    if not price_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid subscription tier",
        )
    
    # Create checkout session
    try:
        session = stripe.checkout.Session.create(
            customer=customer_id,
            mode="subscription",
            payment_method_types=["card"],
            line_items=[
                {
                    "price": price_id,
                    "quantity": data.seats or 1,
                }
            ],
            success_url=f"{data.success_url}?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=data.cancel_url,
            metadata={
                "organization_id": org.id,
                "tier": data.tier,
            },
            subscription_data={
                "metadata": {
                    "organization_id": org.id,
                    "tier": data.tier,
                }
            },
        )
        
        return CreateCheckoutResponse(
            session_id=session.id,
            url=session.url,
        )
    
    except stripe.error.StripeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ============================================================================
# Customer Portal
# ============================================================================

@router.post("/portal", response_model=PortalSessionResponse)
async def create_portal_session(
    return_url: str,
    org: Organization = Depends(get_current_org),
    user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Create a Stripe customer portal session."""
    if not stripe.api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is not configured",
        )
    
    if not org.stripe_customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No billing account found. Please subscribe first.",
        )
    
    try:
        session = stripe.billing_portal.Session.create(
            customer=org.stripe_customer_id,
            return_url=return_url,
        )
        
        return PortalSessionResponse(url=session.url)
    
    except stripe.error.StripeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ============================================================================
# Invoices
# ============================================================================

@router.get("/invoices", response_model=List[InvoiceResponse])
async def list_invoices(
    limit: int = 10,
    org: Organization = Depends(get_current_org),
):
    """List organization invoices."""
    if not stripe.api_key or not org.stripe_customer_id:
        return []
    
    try:
        invoices = stripe.Invoice.list(
            customer=org.stripe_customer_id,
            limit=limit,
        )
        
        return [
            InvoiceResponse(
                id=inv.id,
                number=inv.number,
                amount_due=inv.amount_due,
                amount_paid=inv.amount_paid,
                currency=inv.currency,
                status=inv.status,
                created=inv.created,
                invoice_pdf=inv.invoice_pdf,
                hosted_invoice_url=inv.hosted_invoice_url,
            )
            for inv in invoices.data
        ]
    
    except stripe.error.StripeError:
        return []


@router.get("/invoices/{invoice_id}", response_model=InvoiceResponse)
async def get_invoice(
    invoice_id: str,
    org: Organization = Depends(get_current_org),
):
    """Get a specific invoice."""
    if not stripe.api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is not configured",
        )
    
    try:
        invoice = stripe.Invoice.retrieve(invoice_id)
        
        # Verify ownership
        if invoice.customer != org.stripe_customer_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invoice not found",
            )
        
        return InvoiceResponse(
            id=invoice.id,
            number=invoice.number,
            amount_due=invoice.amount_due,
            amount_paid=invoice.amount_paid,
            currency=invoice.currency,
            status=invoice.status,
            created=invoice.created,
            invoice_pdf=invoice.invoice_pdf,
            hosted_invoice_url=invoice.hosted_invoice_url,
        )
    
    except stripe.error.StripeError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invoice not found",
        )


# ============================================================================
# Pricing
# ============================================================================

@router.get("/prices", response_model=List[PriceResponse])
async def get_prices():
    """Get available subscription prices."""
    return [
        PriceResponse(
            tier=SubscriptionTier.FREE,
            name="Free",
            description="For individuals and small teams",
            price=0,
            currency="usd",
            interval="month",
            features=[
                "5 team members",
                "1 GB storage",
                "10,000 API calls/month",
                "Community support",
            ],
        ),
        PriceResponse(
            tier=SubscriptionTier.STARTER,
            name="Starter",
            description="For growing teams",
            price=2900,  # cents
            currency="usd",
            interval="month",
            features=[
                "25 team members",
                "10 GB storage",
                "100,000 API calls/month",
                "Email support",
                "Advanced analytics",
            ],
        ),
        PriceResponse(
            tier=SubscriptionTier.PRO,
            name="Pro",
            description="For professional teams",
            price=9900,
            currency="usd",
            interval="month",
            features=[
                "Unlimited team members",
                "100 GB storage",
                "1,000,000 API calls/month",
                "Priority support",
                "SSO/SAML",
                "Custom integrations",
            ],
        ),
        PriceResponse(
            tier=SubscriptionTier.ENTERPRISE,
            name="Enterprise",
            description="For large organizations",
            price=None,  # Custom pricing
            currency="usd",
            interval="month",
            features=[
                "Everything in Pro",
                "Unlimited storage",
                "Unlimited API calls",
                "Dedicated support",
                "SLA guarantee",
                "Custom deployment",
            ],
        ),
    ]


# ============================================================================
# Subscription Changes
# ============================================================================

@router.post("/cancel")
async def cancel_subscription(
    at_period_end: bool = True,
    org: Organization = Depends(get_current_org),
    db = Depends(get_db),
):
    """Cancel the current subscription."""
    billing_service = BillingService(db)
    subscription = await billing_service.get_subscription(org.id)
    
    if not subscription or not subscription.stripe_subscription_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active subscription to cancel",
        )
    
    try:
        if at_period_end:
            stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=True,
            )
        else:
            stripe.Subscription.delete(subscription.stripe_subscription_id)
        
        await billing_service.mark_subscription_canceled(org.id)
        
        return {"message": "Subscription canceled"}
    
    except stripe.error.StripeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/reactivate")
async def reactivate_subscription(
    org: Organization = Depends(get_current_org),
    db = Depends(get_db),
):
    """Reactivate a canceled subscription."""
    billing_service = BillingService(db)
    subscription = await billing_service.get_subscription(org.id)
    
    if not subscription or not subscription.stripe_subscription_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No subscription to reactivate",
        )
    
    try:
        stripe.Subscription.modify(
            subscription.stripe_subscription_id,
            cancel_at_period_end=False,
        )
        
        await billing_service.reactivate_subscription(org.id)
        
        return {"message": "Subscription reactivated"}
    
    except stripe.error.StripeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
