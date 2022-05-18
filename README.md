Instructions for crc-k8s-proxy usage
====================================

**NEVER EVER HOOK THIS UP TO A PRODUCTION SYSTEM THIS IS FOR TESTING ONLY**

**CREATE A SEPARATE SERVICE ACCOUNT WITH THE LIMITED ACCESS YOU REQUIRE AND USE THAT FOR YOUR TOKEN**

Checkout namespace *(Note this only works if this is your only namespace - if you already have one just run the command and assign the variable manually as you will be asked if you really want another environment)*
```
export NAMESPACE=`bonfire namespace reserve`
```
Get hostname
```
export HOSTNAME=`oc get env env-$NAMESPACE -o json | jq -r '.status.hostname'`
```
Create Env File called envfile. The hostname above will be in the form of <hostname prefix>.<hostname suffix domain>. For example host-23r09u-20932r.some.other.domain. Split this like this to get the Keycloak URL. host-23r09u-20932r-auth.some.other.domain.
```
K8SURL=<full k8s cluster url>
TOKEN=<token for k8s auth>
KEYCLOAK_URL=https://<hostname-prefix>-auth.<hostname suffix domain>/auth/realms/redhat-external
HOSTNAME=<hostname from above>
PROXYSSL=true
```
Deploy HAC frontend
```
bonfire deploy hac -n $NAMESPACE --frontends true
```
OC process and deploy
```
oc process -f https://raw.githubusercontent.com/RedHatInsights/crc-k8s-proxy/master/deploy.yaml -n $NAMESPACE --param-file=envfile --local | oc apply -f - -n $NAMESPACE
```
Get creds
```
oc get secret env-$NAMESPACE-keycloak -n $NAMESPACE -o json | jq '.data | map_values(@base64d)'
```
Open browser to... 
```
echo https://$HOSTNAME/hac/app-studio
```
Enter "default" creds in UI