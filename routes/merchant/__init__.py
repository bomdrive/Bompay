"""
Merchant routes package — each sub-module handles one domain.
Legacy routes preserved in legacy.py while new services get their own files.
"""
from fastapi import APIRouter

from .legacy import router as _legacy_router
from .storefront import router as storefront_router
from .products import router as products_router
from .orders import router as orders_router
from .payment_links import router as payment_links_router
from .customers import router as customers_router
from .discounts import router as discounts_router
from .team import router as team_router
from .roles_api import router as roles_router
from .audit_api import router as audit_router

router = APIRouter()
router.include_router(_legacy_router)
router.include_router(storefront_router)
router.include_router(products_router)
router.include_router(orders_router)
router.include_router(payment_links_router)
router.include_router(customers_router)
router.include_router(discounts_router)
router.include_router(team_router)
router.include_router(roles_router)
router.include_router(audit_router)
