<?php


namespace SimpleSAML\Module\webauthn\WebAuthn;


class StateData
{





    //jen proměnné co používá registration.php



    /**
     * backend storage configuration. Required.
     *
     * @var \SimpleSAML\Module\webauthn\Store
     */
    public $store;

    /**
     * Scope of the FIDO2 attestation. Can only be in the own domain.
     *
     * @var string|null
     */
    public $scope = null;

    /**
     * The scope derived from the SimpleSAMLphp configuration;
     * can be null due to misconfiguration, in case we cannot warn the administrator on a mismatching scope
     *
     * @var string|null
     */
    public $derivedScope = null;

    /**
     * attribute to use as username for the FIDO2 attestation.
     *
     * @var string
     */
    public $usernameAttrib;

    /**
     * attribute to use as display name for the FIDO2 attestation.
     *
     * @var string
     */
    public $displaynameAttrib;

    /**
     * @var boolean
     */
    public $requestTokenModel;

    /**
     * @var boolean should new users be considered as enabled by default?
     */
    public $defaultEnabled;

    /**
     * @var boolean switch that determines how $toggle will be used, if true then value of $toggle
     *              will mean whether to trigger (true) or not (false) the webauthn authentication,
     *              if false then $toggle means whether to switch the value of $defaultEnabled and then use that
     */
    public $force;

    /**
     * @var boolean an attribute which is associated with $force because it determines its meaning,
     *              it either simply means whether to trigger webauthn authentication or switch the default settings,
     *              if null (was not sent as attribute) then the information from database is used
     */
    public $toggleAttrib;

    /**
     * @var bool a bool that determines whether to use local database or not
     */
    public $useDatabase;

    /**
     * @var string|null AuthnContextClassRef
     */
    public $authnContextClassRef = null;

    /**
     * @var bool an attribute which determines whether you will be able to register and manage tokens
     *           while authenticating or you want to use the standalone registration page for these
     *           purposes. If set to false => standalone registration page, if false => inflow registration.
     *           If parameter from configuration is not explicitly set, it is set to true.
     */
    public $useInflowRegistration;
}