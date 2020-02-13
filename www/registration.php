<?php

/**
 * construct relevant page variables for FIDO registration, authentication and
 * token management
 *
 * @package SimpleSAMLphp
 */

use SimpleSAML\Auth;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\Auth\Process\WebAuthn;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Utils;
use Webmozart\Assert\Assert;

function saveStateAndRedirect(&$state) {
    $id = Auth\State::saveState($state, 'webauthn:request');
    $url = Module::getModuleURL('webauthn/webauthn.php');
    Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);
}
function prepareState($stateData, &$state) {

    $state['requestTokenModel'] = $stateData->requestTokenModel;
    $state['webauthn:store'] = $stateData->store;
    $state['FIDO2Tokens'] = $stateData->store->getTokenData($state['Attributes'][$stateData->usernameAttrib][0]);
    $state['FIDO2Scope'] = $stateData->scope;
    $state['FIDO2DerivedScope'] = $stateData->derivedScope;

    $state['FIDO2Username'] = $state['Attributes'][$stateData->usernameAttrib][0];
    $state['FIDO2Displayname'] = $state['Attributes'][$stateData->displaynameAttrib][0]; //NEBUDE FUNGOVAT KVŮLI DVĚMA DRUHŮM JMEN

    $state['FIDO2SignupChallenge'] = hash('sha512', random_bytes(64));

    $state['FIDO2WantsRegister'] = false;
    $state['FIDO2AuthSuccessful'] = false;
    $state['UseInflowRegistration'] = $stateData->useInflowRegistration;

}

$config = Configuration::getOptionalConfig('module_webauthn.php')->toArray();
assert(is_array($config));
$uidAttribute = $config['attrib_username'];
$as = new Simple('default-sp');
$stateData = new StateData();
$as->requireAuth();
$attrs = $as->getAttributes();
//$attrs['uid'] = $attrs[$config['attrib_username']];
//$attrs['displayName'] = $attrs[$config['attrib_displayname']];

$state['Attributes'] = $attrs;

$stateData->requestTokenModel = $config['request_tokenmodel'];
$stateData->store = Store::parseStoreConfig($config['store']); // exception
$stateData->scope = $config['scope'];
$baseurl = Utils\HTTP::getSelfHost();
$hostname = parse_url($baseurl, PHP_URL_HOST);
if ($hostname !== null) {
    $stateData->derivedScope = $hostname;
}
$stateData->usernameAttrib = $config['attrib_username'];
$stateData->displaynameAttrib = $config['attrib_displayname'];
$stateData->useInflowRegistration = true;

prepareState($stateData, $state);



$metadataHandler = MetaDataStorageHandler::getMetadataHandler();
$metadata = $metadataHandler->getMetaDataCurrent('saml20-idp-hosted');
$state['Source'] = $metadata;
$state['IdPMetadata'] = $metadata;
$state['Registration'] = true;
$state['FIDO2AuthSuccessful'] = $state['FIDO2Tokens'][0][0];
$state['FIDO2WantsRegister'] = true;
saveStateAndRedirect($state);


