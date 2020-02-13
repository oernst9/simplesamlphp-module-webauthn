<?php

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @author Stefan Winter <stefan.winter@restena.lu>
 * @package SimpleSAMLphp
 */

namespace SimpleSAML\Module\webauthn\Auth\Process;

use _HumbugBox3ab8cff0fda0\FFI\Exception;
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Utils;

class WebAuthn extends Auth\ProcessingFilter
{
    private $stateData;
    /**
     * Initialize filter.
     *
     * Validates and parses the configuration.
     *
     * @param array $config Configuration information.
     * @param mixed $reserved For future use.
     *
     * @throws \SimpleSAML\Error\Exception if the configuration is not valid.
     */
    public function __construct($config, $reserved)
    {
        /**
         * Remove annotation + assert as soon as this method can be typehinted (SSP 2.0)
         * @psalm-suppress RedundantConditionGivenDocblockType
         */
        assert(is_array($config));
        parent::__construct($config, $reserved);
        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();
        try {
            $this->stateData->store = Store::parseStoreConfig($moduleConfig['store']);
        } catch (\Exception $e) {
            Logger::error(
                'webauthn: Could not create storage: ' .
                $e->getMessage()
            );
        }

        // Set the optional scope if set by configuration
        if (array_key_exists('scope', $moduleConfig)) {
            $this->stateData->scope = $moduleConfig['scope'];
        }

        // Set the derived scope so we can compare it to the sent host at a later point
        $baseurl = Utils\HTTP::getSelfHost();
        $hostname = parse_url($baseurl, PHP_URL_HOST);
        if ($hostname !== null) {
            $this->stateData->derivedScope = $hostname;
        }

        if (array_key_exists('attrib_username', $moduleConfig)) {
            $this->stateData->usernameAttrib = $moduleConfig['attrib_username'];
        } else {
            throw new Error\CriticalConfigurationError('webauthn: it is required to set attrib_username in config.');
        }

        if (array_key_exists('attrib_displayname', $moduleConfig)) {
            $this->stateData->displaynameAttrib = $moduleConfig['attrib_displayname'];
        } else {
            throw new Error\CriticalConfigurationError('webauthn: it is required to set attrib_displayname in config.');
        }

        if (array_key_exists('request_tokenmodel', $moduleConfig)) {
            $this->stateData->requestTokenModel = $moduleConfig['request_tokenmodel'];
        } else {
            $this->stateData->requestTokenModel = false;
        }
        if (array_key_exists('default_enable', $moduleConfig)) {
            $this->stateData->defaultEnabled = $moduleConfig['default_enable'];
        } else {
            $this->stateData->defaultEnabled = false;
        }

        if (array_key_exists('force', $moduleConfig)) {
            $this->stateData->force = $moduleConfig['force'];
        } else {
            $this->stateData->force = true;
        }
        if (array_key_exists('attrib_toggle', $moduleConfig)) {
            $this->stateData->toggleAttrib = $moduleConfig['attrib_toggle'];
        } else {
            $this->stateData->toggleAttrib = 'toggle';
        }
        if (array_key_exists('use_database', $moduleConfig)) {
            $this->stateData->useDatabase = $moduleConfig['use_database'];
        } else {
            $this->stateData->useDatabase = true;
        }
        if (array_key_exists('authnContextClassRef', $moduleConfig)) {
            $this->stateData->authnContextClassRef = $moduleConfig['authnContextClassRef'];

        }
        if (array_key_exists('use_inflow_registration', $moduleConfig)) {
            $this->stateData->useInflowRegistration = $moduleConfig['use_inflow_registration'];
        } else {
            $this->stateData->useInflowRegistration = true;
        }
    }
    /**
     * Process a authentication response
     *
     * This function saves the state, and redirects the user to the page where
     * the user can register or authenticate with his token.
     *
     * @param array &$state The state of the response.
     *
     * @return void
     */
    public function process(&$state)
    {
        /**
         * Remove annotation + assert as soon as this method can be typehinted (SSP 2.0)
         * @psalm-suppress RedundantConditionGivenDocblockType
         */
        assert(is_array($state));
        assert(array_key_exists('UserID', $state));
        assert(array_key_exists('Destination', $state));
        assert(array_key_exists('entityid', $state['Destination']));
        assert(array_key_exists('metadata-set', $state['Destination']));
        assert(array_key_exists('entityid', $state['Source']));
        assert(array_key_exists('metadata-set', $state['Source']));
        if (!array_key_exists($this->stateData->usernameAttrib, $state['Attributes'])) {
            Logger::warning('webauthn: cannot determine if user needs second factor, missing attribute "' .
                $this->stateData->usernameAttrib . '".');
            return;
        }
        $state['saml:AuthnContextClassRef'] = $this->authnContextClassRef ?? 'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO';

        Logger::debug('webauthn: userid: ' . $state['Attributes'][$this->usernameAttrib][0]);

        $localToggle = !empty($state['Attributes'][$this->toggleAttrib])
            && !empty($state['Attributes'][$this->toggleAttrib][0]);
        if (
            $this->store->is2FAEnabled(
                $state['Attributes'][$this->usernameAttrib][0],
                $this->defaultEnabled,
                $this->useDatabase,
                $localToggle,
                $this->force
            ) === false
        ) {
            // nothing to be done here, end authprocfilter processing
            return;
        }
        self::prepareState($this->stateData, $state);
        self::saveStateAndRedirect($state);

    }

    //do vlastní třídy
    public static function saveStateAndRedirect(&$state) {
        $id = Auth\State::saveState($state, 'webauthn:request');
        $url = Module::getModuleURL('webauthn/webauthn.php');
        Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }

    public static function prepareState($stateData, &$state) {

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

}