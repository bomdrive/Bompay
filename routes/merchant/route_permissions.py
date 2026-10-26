"""
BOMPAY Merchant Route Permission Map.

Maps HTTP (method, path_prefix) → required permission(s).
Used by the RBAC middleware in server.py to enforce permissions
on team members WITHOUT modifying each individual route handler.

Business owners bypass all checks (they hold ALL_PERMISSIONS).

Convention:
  - Use the *most specific* prefix that identifies the route.
  - For routes that share the same prefix, list the more specific one first.
  - Patterns are checked in order; the first match wins.
"""

from typing import List, Tuple

# List of (method, path_prefix, [permissions])
# method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "*" (any)
ROUTE_PERMISSION_MAP: List[Tuple[str, str, List[str]]] = [
    # Dashboard
    ("GET",    "/api/v1/merchant/dashboard",                         ["dashboard.read"]),

    # Accounts
    ("GET",    "/api/v1/merchant/accounts",                          ["accounts.read"]),
    ("POST",   "/api/v1/merchant/accounts",                          ["accounts.read"]),

    # Transactions
    ("GET",    "/api/v1/merchant/transactions",                      ["transactions.read"]),

    # KYB
    ("GET",    "/api/v1/merchant/kyb",                               ["kyb.read"]),
    ("POST",   "/api/v1/merchant/kyb/upload",                        ["kyb.submit"]),
    ("POST",   "/api/v1/merchant/kyb/verify-identity",               ["kyb.submit"]),
    ("POST",   "/api/v1/merchant/kyb/validate-identity",             ["kyb.submit"]),
    ("POST",   "/api/v1/merchant/kyb",                               ["kyb.submit"]),

    # API Keys
    ("GET",    "/api/v1/merchant/api-keys",                          ["developer.api_keys.read"]),
    ("POST",   "/api/v1/merchant/api-keys/regenerate",               ["developer.api_keys.rotate"]),
    ("POST",   "/api/v1/merchant/api-keys",                          ["developer.api_keys.create"]),

    # Webhooks
    ("GET",    "/api/v1/merchant/webhook",                           ["developer.webhooks.read"]),
    ("PUT",    "/api/v1/merchant/webhook",                           ["developer.webhooks.write"]),

    # Mode switch
    ("PUT",    "/api/v1/merchant/mode",                              ["settings.update"]),

    # Notification preferences
    ("GET",    "/api/v1/merchant/notifications/preferences",         ["settings.read"]),
    ("PUT",    "/api/v1/merchant/notifications/preferences",         ["settings.update"]),

    # Disputes
    ("GET",    "/api/v1/merchant/disputes",                          ["disputes.read"]),
    ("POST",   "/api/v1/merchant/disputes",                          ["disputes.write"]),

    # Transfers
    ("POST",   "/api/v1/merchant/services/transfer",                 ["transfers.initiate"]),
    ("GET",    "/api/v1/merchant/services/banks",                    ["accounts.read"]),
    ("POST",   "/api/v1/merchant/services/name-enquiry",             ["transfers.initiate"]),

    # VAS services
    ("GET",    "/api/v1/merchant/services/data-plans",               ["services.use"]),
    ("GET",    "/api/v1/merchant/services/cable-plans",              ["services.use"]),
    ("POST",   "/api/v1/merchant/services/validate",                 ["services.use"]),
    ("POST",   "/api/v1/merchant/services/airtime",                  ["services.use"]),
    ("POST",   "/api/v1/merchant/services/data",                     ["services.use"]),
    ("POST",   "/api/v1/merchant/services/electricity",              ["services.use"]),
    ("POST",   "/api/v1/merchant/services/cable",                    ["services.use"]),

    # Logs
    ("GET",    "/api/v1/merchant/logs",                              ["developer.logs.read"]),

    # Settings
    ("PUT",    "/api/v1/merchant/settings",                          ["settings.update"]),

    # Team Management
    ("GET",    "/api/v1/merchant/team/members",                      ["team.members.read"]),
    ("PATCH",  "/api/v1/merchant/team/members",                      ["team.members.update"]),
    ("DELETE", "/api/v1/merchant/team/members",                      ["team.members.remove"]),
    ("POST",   "/api/v1/merchant/team/invite",                       ["team.members.invite"]),
    ("GET",    "/api/v1/merchant/team/invitations",                  ["team.members.invite"]),
    ("DELETE", "/api/v1/merchant/team/invitations",                  ["team.members.invite"]),

    # Roles
    ("GET",    "/api/v1/merchant/roles",                             ["team.roles.read"]),
    ("POST",   "/api/v1/merchant/roles",                             ["team.roles.create"]),
    ("PATCH",  "/api/v1/merchant/roles",                             ["team.roles.update"]),
    ("DELETE", "/api/v1/merchant/roles",                             ["team.roles.delete"]),

    # Audit Logs
    ("GET",    "/api/v1/merchant/audit-logs",                        ["audit.read"]),

    # Transfer Approvals
    ("GET",    "/api/v1/merchant/transfer-requests",                 ["transfers.initiate"]),
    ("POST",   "/api/v1/merchant/transfer-requests",                 ["transfers.initiate"]),

    # Storefront
    ("GET",    "/api/v1/stores",                                     ["storefront.read"]),
    ("POST",   "/api/v1/stores",                                     ["storefront.write"]),
    ("PATCH",  "/api/v1/stores",                                     ["storefront.write"]),
    ("POST",   "/api/v1/stores",                                     ["storefront.write"]),

    # Payment Links
    ("GET",    "/api/v1/payment-links",                              ["payment_links.read"]),
    ("POST",   "/api/v1/payment-links",                              ["payment_links.write"]),
    ("PATCH",  "/api/v1/payment-links",                              ["payment_links.write"]),

    # Checkout sessions
    ("GET",    "/api/v1/merchant/checkout",                          ["developer.checkout.read"]),
]


def get_required_permissions(method: str, path: str) -> List[str]:
    """
    Return the required permission list for a given HTTP method + path.
    Returns an empty list if no match is found (unenforced route).
    """
    for m, prefix, perms in ROUTE_PERMISSION_MAP:
        if (m == "*" or m == method) and path.startswith(prefix):
            return perms
    return []
