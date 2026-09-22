"""Register the local chain and the FermionWallet Safe App in the Safe Config Service.

Runs once, inside the safe-config-service image (`python src/manage.py shell`),
after migrations and before cfg-web starts. It replaces the manual steps of
safe-infrastructure's docs/running_locally.md (ChainInfo via the admin UI).
Idempotent: rerunning updates the same rows.
"""
import os

from chains.models import Chain, Feature, Service
from safe_apps.models import SafeApp

CHAIN_ID = 31337
PUBLIC = os.environ.get("DEMO_PUBLIC_URL", "http://localhost:8000")
APP_URL = os.environ.get("FERMION_APP_URL", "http://localhost:8001/safe-app")

chain, _ = Chain.objects.update_or_create(
    id=CHAIN_ID,
    defaults=dict(
        name="FermionWallet Demo (anvil)",
        short_name="fwdemo",
        description="Local anvil chain of the FermionWallet demo",
        l2=True,
        is_testnet=True,
        relevance=1,
        # The browser reaches the chain through the stack's reverse proxy; the
        # Client Gateway (inside the network) uses vpc_rpc_uri.
        rpc_uri=f"{PUBLIC}/rpc",
        safe_apps_rpc_uri=f"{PUBLIC}/rpc",
        public_rpc_uri=f"{PUBLIC}/rpc",
        vpc_rpc_uri="http://chain:8545",
        block_explorer_uri_address_template=f"{PUBLIC}/address/{{{{address}}}}",
        block_explorer_uri_tx_hash_template=f"{PUBLIC}/tx/{{{{txHash}}}}",
        block_explorer_uri_api_template=f"{PUBLIC}/api?module={{{{module}}}}&action={{{{action}}}}&address={{{{address}}}}&apiKey={{{{apiKey}}}}",
        currency_name="Ether",
        currency_symbol="ETH",
        currency_decimals=18,
        currency_logo_uri="demo/eth.svg",
        chain_logo_uri="demo/chain.svg",
        transaction_service_uri="http://nginx:8000/txs",
        vpc_transaction_service_uri="http://nginx:8000/txs",
        theme_text_color="#ffffff",
        theme_background_color="#0b3d3a",
        recommended_master_copy_version="1.4.1",
        # Safe v1.4.1 canonical deployments, installed on the chain by
        # demo/wallet/install_safe_contracts.py.
        safe_singleton_address="0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
        safe_proxy_factory_address="0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
        multi_send_address="0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526",
        multi_send_call_only_address="0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
        fallback_handler_address="0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99",
        sign_message_lib_address="0xd53cd0aB83D845Ac265BE939c57F53AD838012c9",
        create_call_address="0x9b35Af71d77eaf8d7e40252370304687390A1A52",
        simulate_tx_accessor_address="0x3d4BA2E0884aa488718476ca2FB8Efc291A46199",
    ),
)

services = [
    Service.objects.update_or_create(key=key, defaults={"name": key})[0]
    for key in ("WALLET_WEB", "CGW")
]
for key in ("SAFE_APPS", "EIP1559", "SAFE_TX_GAS_OPTIONAL", "ERC721", "SEND_FLOW", "CLASSIC_VIEW"):
    feature, _ = Feature.objects.get_or_create(key=key)
    feature.chains.add(chain)
    feature.services.add(*services)

SafeApp.objects.update_or_create(
    url=APP_URL,
    defaults=dict(
        name="FermionWallet",
        description="Post-quantum second authorization: approve queued Safe transactions on your Ledger with hybrid ECDSA + XMSS signatures.",
        chain_ids=[CHAIN_ID],
        icon_url="demo/fermionwallet.svg",
        listed=True,
        featured=True,
    ),
)
print(f"cfg bootstrap: chain {CHAIN_ID} + FermionWallet Safe App ({APP_URL}) registered")
