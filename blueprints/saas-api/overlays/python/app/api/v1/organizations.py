"""
Organizations API Routes
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query

from app.dependencies import get_db, get_current_user, get_current_org, require_role
from app.models import User, Organization, OrganizationMember, UserRole
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationListResponse,
    MemberResponse,
    MemberInvite,
    MemberUpdate,
)
from app.services.organization_service import OrganizationService


router = APIRouter()


# ============================================================================
# Organization CRUD
# ============================================================================

@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    data: OrganizationCreate,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Create a new organization."""
    org_service = OrganizationService(db)
    
    # Check slug uniqueness
    if await org_service.get_by_slug(data.slug):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization slug already taken",
        )
    
    org = await org_service.create(data, owner=current_user)
    return org


@router.get("/", response_model=OrganizationListResponse)
async def list_organizations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """List organizations for current user."""
    org_service = OrganizationService(db)
    orgs, total = await org_service.list_for_user(
        user_id=current_user.id,
        page=page,
        page_size=page_size,
    )
    
    return OrganizationListResponse(
        items=orgs,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{org_slug}", response_model=OrganizationResponse)
async def get_organization(
    org_slug: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Get organization by slug."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check membership
    if not await org_service.is_member(org.id, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this organization",
        )
    
    return org


@router.patch("/{org_slug}", response_model=OrganizationResponse)
async def update_organization(
    org_slug: str,
    data: OrganizationUpdate,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Update organization (admin/owner only)."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check permission
    role = await org_service.get_user_role(org.id, current_user.id)
    if role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    # Check slug uniqueness if changing
    if data.slug and data.slug != org.slug:
        if await org_service.get_by_slug(data.slug):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization slug already taken",
            )
    
    updated_org = await org_service.update(org.id, data)
    return updated_org


@router.delete("/{org_slug}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_slug: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Delete organization (owner only)."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check owner permission
    role = await org_service.get_user_role(org.id, current_user.id)
    if role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner access required",
        )
    
    await org_service.delete(org.id)
    return None


# ============================================================================
# Member Management
# ============================================================================

@router.get("/{org_slug}/members", response_model=List[MemberResponse])
async def list_members(
    org_slug: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """List organization members."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check membership
    if not await org_service.is_member(org.id, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this organization",
        )
    
    members = await org_service.list_members(org.id)
    return members


@router.post("/{org_slug}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
async def invite_member(
    org_slug: str,
    data: MemberInvite,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Invite a new member to organization."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check permission
    role = await org_service.get_user_role(org.id, current_user.id)
    if role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to invite members",
        )
    
    # Check if user exists
    from app.services.user_service import UserService
    user_service = UserService(db)
    user = await user_service.get_by_email(data.email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found with this email",
        )
    
    # Check if already a member
    if await org_service.is_member(org.id, user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a member",
        )
    
    # Prevent granting higher role than requester
    if data.role == UserRole.OWNER and role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can grant owner role",
        )
    
    member = await org_service.add_member(org.id, user.id, data.role)
    return member


@router.patch("/{org_slug}/members/{user_id}", response_model=MemberResponse)
async def update_member_role(
    org_slug: str,
    user_id: int,
    data: MemberUpdate,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Update member's role."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check permission
    requester_role = await org_service.get_user_role(org.id, current_user.id)
    if requester_role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    # Can't change own role
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role",
        )
    
    # Only owners can grant/change owner role
    target_role = await org_service.get_user_role(org.id, user_id)
    if (data.role == UserRole.OWNER or target_role == UserRole.OWNER) and requester_role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can modify owner roles",
        )
    
    member = await org_service.update_member_role(org.id, user_id, data.role)
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )
    
    return member


@router.delete("/{org_slug}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    org_slug: str,
    user_id: int,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Remove member from organization."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check permission
    requester_role = await org_service.get_user_role(org.id, current_user.id)
    
    # Users can remove themselves
    if user_id != current_user.id:
        if requester_role not in (UserRole.OWNER, UserRole.ADMIN):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required to remove members",
            )
        
        # Only owners can remove other owners
        target_role = await org_service.get_user_role(org.id, user_id)
        if target_role == UserRole.OWNER and requester_role != UserRole.OWNER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners can remove other owners",
            )
    
    # Prevent removing last owner
    if requester_role == UserRole.OWNER:
        owner_count = await org_service.count_owners(org.id)
        if owner_count <= 1 and user_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last owner. Transfer ownership first.",
            )
    
    await org_service.remove_member(org.id, user_id)
    return None


# ============================================================================
# Leave Organization
# ============================================================================

@router.post("/{org_slug}/leave", status_code=status.HTTP_204_NO_CONTENT)
async def leave_organization(
    org_slug: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Leave an organization."""
    org_service = OrganizationService(db)
    org = await org_service.get_by_slug(org_slug)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    
    # Check if last owner
    role = await org_service.get_user_role(org.id, current_user.id)
    if role == UserRole.OWNER:
        owner_count = await org_service.count_owners(org.id)
        if owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot leave as the last owner. Transfer ownership first.",
            )
    
    await org_service.remove_member(org.id, current_user.id)
    return None
