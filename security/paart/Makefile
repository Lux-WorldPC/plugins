PLUGIN_NAME=		paart
PLUGIN_VERSION=		1.0
PLUGIN_COMMENT=		Managed VPN user access for existing WireGuard instances
PLUGIN_MAINTAINER=	fm@lwpc.lu
PLUGIN_WWW=		https://paart.app

# No PLUGIN_DEPENDS on purpose. The plugin is pure PHP MVC with no daemon
# and no third-party binary (D3), and WireGuard itself has been part of the
# OPNsense CORE since 24.1 — verified on 26.1.11, where the model files
# belong to the opnsense package and no os-wireguard package exists.
# Declaring a dependency on it would make `pkg install os-paart` fail.
#
# PLUGIN_LICENSE defaults to BSD2CLAUSE and PLUGIN_TIER to 3 in plugins.mk,
# which is what this plugin wants (ADR 0014, open core).

.include "../../Mk/plugins.mk"
