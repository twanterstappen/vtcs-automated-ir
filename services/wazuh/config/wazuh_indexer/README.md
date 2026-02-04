# Custom OpenSearch Roles Configuration

Deze directory bevat custom role configuraties voor OpenSearch Security (Wazuh Indexer).

## Bestanden

### roles.yml
Definieert custom roles met specifieke permissions:
- **custom_readonly_role**: Read-only rol met:
  - Cluster permissions: `cluster_composite_ops_ro`
  - Index permissions: Read access op alle indices (`*`)
  - Tenant permissions: Global tenant access

### roles_mapping.yml
Mapt roles naar backend_roles of users:
- **custom_readonly**: Backend role voor de custom_readonly_role

## Gebruik

### Gebruiker aanmaken met custom role

1. Voeg een gebruiker toe aan `internal_users.yml.example`:
```yaml
custom_user:
  hash: "{CUSTOM-USER-PASSWORD-HASH}"
  reserved: false
  backend_roles:
    - "custom_readonly"
  description: "Custom read-only user"
```

2. Update het `.env` bestand:
```bash
CUSTOM_USER_PASSWORD=uw-sterke-wachtwoord
```

3. Update `setup.ps1` om de hash te genereren voor custom_user.

4. Run het setup script:
```powershell
.\setup.ps1
```

### Alternatief: Rol toewijzen aan bestaande gebruiker

Via de OpenSearch Dashboards Security UI:
1. Log in als admin op https://localhost:443
2. Navigeer naar: Menu → Security → Roles
3. Verifieer dat `custom_readonly_role` aanwezig is
4. Ga naar Security → Internal Users
5. Selecteer een gebruiker en voeg de backend role `custom_readonly` toe

### Alternatief: Via REST API

```bash
# Rol toewijzen aan een gebruiker
curl -X PUT "https://localhost:9200/_plugins/_security/api/internalusers/username" \
  -u "admin:your-password" \
  -H 'Content-Type: application/json' \
  -d '{
    "backend_roles": ["custom_readonly"]
  }'
```

## Rol permissions uitleg

- **cluster_composite_ops_ro**: Read-only cluster operations (bijv. cluster health, stats)
- **Index patterns "*"**: Toegang tot alle indices
- **Allowed actions**: 
  - `read`: Basis read operatie
  - `indices:data/read/*`: Alle data read operaties
  - `indices:admin/mappings/get`: Index mappings inzien
  - `indices:admin/get`: Index metadata inzien
- **Tenant "global_tenant"**: Toegang tot de global tenant voor dashboards

## Automatisering

De configuratie wordt automatisch geladen bij container start via volume mounts in `docker-compose.yml`:
```yaml
- ./services/wazuh/config/wazuh_indexer/roles.yml:/usr/share/wazuh-indexer/config/opensearch-security/roles.yml
- ./services/wazuh/config/wazuh_indexer/roles_mapping.yml:/usr/share/wazuh-indexer/config/opensearch-security/roles_mapping.yml
```

Na wijzigingen:
```powershell
docker compose restart wazuh.indexer
```

Of forceer security index reload:
```bash
docker exec -it wazuh.indexer bash
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/wazuh-indexer/config/opensearch-security/ \
  -icl -nhnv \
  -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
  -cert /usr/share/wazuh-indexer/config/certs/admin.pem \
  -key /usr/share/wazuh-indexer/config/certs/admin-key.pem
```
