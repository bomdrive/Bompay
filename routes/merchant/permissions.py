"""
BOMPAY Merchant RBAC — Centralized Permission Catalogue & System Roles.

ALL permission strings live here. Import from this module everywhere.
"""
from typing import Dict, List, Set

# ─── PERMISSION CATALOGUE ─────────────────────────────────────────────────────

PERMISSIONS: Dict[str, str] = {
    # Dashboard
    "dashboard.read": "View dashboard and analytics",

    # Accounts
    "accounts.read": "View virtual accounts and balances",

    # Transactions
    "transactions.read": "View transaction history",
    "transactions.export": "Export transaction data",

    # Transfers (maker-checker)
    "transfers.initiate": "Initiate bank transfers",
    "transfers.approve": "Approve or reject pending transfers",

    # VAS Services
    "services.use": "Use VAS services (airtime, data, electricity, cable TV)",

    # Developer / API
    "developer.api_keys.read": "View API keys",
    "developer.api_keys.create": "Create new API keys",
    "developer.api_keys.delete": "Delete API keys",
    "developer.api_keys.rotate": "Regenerate / rotate API keys",
    "developer.webhooks.read": "View webhooks",
    "developer.webhooks.write": "Create, update, or delete webhooks",
    "developer.logs.read": "View developer and activity logs",
    "developer.checkout.read": "View checkout sessions",

    # KYB
    "kyb.read": "View KYB status and uploaded documents",
    "kyb.submit": "Submit or update KYB documents",

    # Settings
    "settings.read": "View account settings and notification preferences",
    "settings.update": "Update account settings, profile, PIN, and password",

    # Team Management
    "team.members.read": "View team members and their roles",
    "team.members.invite": "Invite new team members",
    "team.members.update": "Change member roles or status",
    "team.members.remove": "Remove/deactivate team members",
    "team.roles.read": "View roles and permission definitions",
    "team.roles.create": "Create custom roles",
    "team.roles.update": "Update custom roles",
    "team.roles.delete": "Delete custom roles",

    # Storefront
    "storefront.read": "View storefront, products, orders, and customers",
    "storefront.write": "Create and manage storefront, products, orders",

    # Payment Links
    "payment_links.read": "View payment links and analytics",
    "payment_links.write": "Create, update, publish, and deactivate payment links",

    # Disputes
    "disputes.read": "View disputes",
    "disputes.write": "Open and respond to disputes",

    # Reports & Audit
    "reports.read": "View reports and analytics",
    "audit.read": "View audit logs",
}

ALL_PERMISSIONS: Set[str] = set(PERMISSIONS.keys())

# Permissions that are read-only (useful for building read-only roles)
READ_PERMISSIONS: Set[str] = {p for p in ALL_PERMISSIONS if p.endswith(".read")}

# ─── SYSTEM ROLES ─────────────────────────────────────────────────────────────
#
# These are seeded once at startup and cannot be modified by merchants.
# role_id values match the keys below (used as stable identifiers).

SYSTEM_ROLES: Dict[str, dict] = {
    "business_owner": {
        "name": "Business Owner",
        "description": "Full access to all features. Cannot be modified or deleted.",
        "permissions": sorted(ALL_PERMISSIONS),
        "is_system": True,
        "protected": True,   # cannot delete or rename
    },
    "full_admin": {
        "name": "Full-Access Admin",
        "description": "Full access except security settings and ownership transfer.",
        "permissions": sorted(ALL_PERMISSIONS - {"settings.update"}),
        "is_system": True,
        "protected": False,
    },
    "read_only_viewer": {
        "name": "Read-Only Viewer",
        "description": "View-only access across all sections. Cannot perform any action.",
        "permissions": sorted(READ_PERMISSIONS | {"audit.read"}),
        "is_system": True,
        "protected": False,
    },
    "finance_manager": {
        "name": "Finance Manager",
        "description": "Manage transfers and financial data. Can approve transfer requests.",
        "permissions": sorted({
            "dashboard.read", "accounts.read",
            "transactions.read", "transactions.export",
            "transfers.initiate", "transfers.approve",
            "reports.read",
        }),
        "is_system": True,
        "protected": False,
    },
    "finance_operator": {
        "name": "Finance Operator",
        "description": "Initiate transfers and view financial data. Transfers need approval.",
        "permissions": sorted({
            "dashboard.read", "accounts.read",
            "transactions.read", "transfers.initiate",
        }),
        "is_system": True,
        "protected": False,
    },
    "developer": {
        "name": "Developer",
        "description": "Manage API keys, webhooks, and view checkout sessions.",
        "permissions": sorted({
            "dashboard.read",
            "developer.api_keys.read", "developer.api_keys.create",
            "developer.api_keys.delete", "developer.api_keys.rotate",
            "developer.webhooks.read", "developer.webhooks.write",
            "developer.logs.read", "developer.checkout.read",
        }),
        "is_system": True,
        "protected": False,
    },
    "store_manager": {
        "name": "Store Manager",
        "description": "Manage storefront, products, and orders.",
        "permissions": sorted({
            "dashboard.read", "storefront.read", "storefront.write",
            "transactions.read", "developer.checkout.read",
        }),
        "is_system": True,
        "protected": False,
    },
    "payment_links_manager": {
        "name": "Payment Links Manager",
        "description": "Create and manage payment links.",
        "permissions": sorted({
            "dashboard.read", "payment_links.read", "payment_links.write",
            "transactions.read",
        }),
        "is_system": True,
        "protected": False,
    },
    "customer_support": {
        "name": "Customer Support",
        "description": "View transactions and manage disputes.",
        "permissions": sorted({
            "dashboard.read", "transactions.read",
            "disputes.read", "disputes.write",
            "developer.checkout.read",
        }),
        "is_system": True,
        "protected": False,
    },
    "auditor": {
        "name": "Auditor / Compliance Viewer",
        "description": "Read-only access across all sections plus audit logs.",
        "permissions": sorted(READ_PERMISSIONS | {"audit.read"}),
        "is_system": True,
        "protected": False,
    },
}

# Roles that can be assigned to invited team members (not owner, which is auto-assigned)
ASSIGNABLE_ROLE_IDS = set(SYSTEM_ROLES.keys()) - {"business_owner"}
