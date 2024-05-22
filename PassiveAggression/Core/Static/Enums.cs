using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;

namespace PassiveAgression.Core.Static
{
    public class Enums
    {
        /// <summary>
        /// DCERPC opnum
        /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3f5d9495-9563-44de-876a-ce6f880e3fb2
        /// </summary>
        public enum OP_DCERPC
        {
            NOTSET = int.MinValue,
            DRSBind = 0,
            DRSUnbind = 1,
            DRSReplicaSync = 2,
            DRSGetNCChanges = 3,
            DRSUpdateRefs = 4,
            DRSReplicaAdd = 5,
            DRSReplicaDel = 6,
            DRSReplicaModify = 7,
            DRSVerifyNames = 8,
            DRSGetMemberships = 9,
            DRSInterDomainMove = 10,
            DRSGetNT4ChangeLog = 11,
            DRSCrackNames = 12,
            DRSWriteSPN = 13,
            DRSRemoveDsServer = 14,
            DRSRemoveDsDomain = 15,
            DRSDomainControllerInfo = 16,
            DRSAddEntry = 17,
            DRSExecuteKCC = 18,
            DRSGetReplInfo = 19,
            DRSAddSidHistory = 20,
            DRSGetMemberships2 = 21,
            DRSReplicaVerifyObjects = 22,
            DRSGetObjectExistence = 23,
            DRSQuerySitesByCost = 24,
            DRSInitDemotion = 25,
            DRSReplicaDemotion = 26,
            DRSFinishDemotion = 27,
            DRSAddCloneDC = 28,
            DRSWriteNgcKey = 29,
            DRSReadNgcKey = 30
        }

        /// <summary>
        /// NETLOGON Opnum
        /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/89f9b028-ee68-4fe2-afca-cc188f7079f7
        /// </summary>
        public enum OP_NETLOGON
        {
            NOTSET = int.MinValue,
            NetrLogonUasLogon = 0,
            NetrLogonUasLogoff = 1,
            NetrLogonSamLogon = 2,
            NetrLogonSamLogoff = 3,
            NetrServerReqChallenge = 4,
            NetrServerAuthenticate = 5,
            NetrServerPasswordSet = 6,
            NetrDatabaseDeltas = 7,
            NetrDatabaseSync = 8,
            NetrAccountDeltas = 9,
            NetrAccountSync = 10,
            NetrGetDCName = 11,
            NetrLogonControl = 12,
            NetrGetAnyDCName = 13,
            NetrLogonControl2 = 14,
            NetrServerAuthenticate2 = 15,
            NetrDatabaseSync2 = 16,
            NetrDatabaseRedo = 17,
            NetrLogonControl2Ex = 18,
            NetrEnumerateTrustedDomains = 19,
            DsrGetDcName = 20,
            NetrLogonDummyRoutine1 = 21, // Deprecated
            NetrLogonGetCapabilities = 21,
            NetrLogonSetServiceBits = 22,
            NetrLogonGetTrustRid = 23,
            NetrLogonComputeServerDigest = 24,
            NetrLogonComputeClientDigest = 25,
            NetrServerAuthenticate3 = 26,
            DsrGetDcNameEx = 27,
            DsrGetSiteName = 28,
            NetrLogonGetDomainInfo = 29,
            NetrServerPasswordSet2 = 30,
            NetrServerPasswordGet = 31,
            NetrLogonSendToSam = 32,
            DsrAddressToSiteNamesW = 33,
            DsrGetDcNameEx2 = 34,
            NetrLogonGetTimeServiceParentDomain = 35,
            NetrEnumerateTrustedDomainsEx = 36,
            DsrAddressToSiteNamesExW = 37,
            DsrGetDcSiteCoverageW = 38,
            NetrLogonSamLogonEx = 39,
            DsrEnumerateDomainTrusts = 40,
            DsrDeregisterDnsHostRecords = 41,
            NetrServerTrustPasswordsGet = 42,
            DsrGetForestTrustInformation = 43,
            NetrGetForestTrustInformation = 44,
            NetrLogonSamLogonWithFlags = 45,
            NetrServerGetTrustInfo = 46,
            OpnumUnused47 = 47,
            DsrUpdateReadOnlyServerDnsRecords = 48
        }

        /// <summary>
        /// SAMR Opnum
        /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1cd138b9-cc1b-4706-b115-49e53189e32e
        /// </summary>
        public enum OP_SAMR
        {
            NOTSET = int.MinValue,
            SamrConnect = 0,
            SamrCloseHandle = 1,
            SamrSetSecurityObject = 2,
            SamrQuerySecurityObject = 3,
            Opnum4NotUsedOnWire = 4,
            SamrLookupDomainInSamServer = 5,
            SamrEnumerateDomainsInSamServer = 6,
            SamrOpenDomain = 7,
            SamrQueryInformationDomain = 8,
            SamrSetInformationDomain = 9,
            SamrCreateGroupInDomain = 10,
            SamrEnumerateGroupsInDomain = 11,
            SamrCreateUserInDomain = 12,
            SamrEnumerateUsersInDomain = 13,
            SamrCreateAliasInDomain = 14,
            SamrEnumerateAliasesInDomain = 15,
            SamrGetAliasMembership = 16,
            SamrLookupNamesInDomain = 17,
            SamrLookupIdsInDomain = 18,
            SamrOpenGroup = 19,
            SamrQueryInformationGroup = 20,
            SamrSetInformationGroup = 21,
            SamrAddMemberToGroup = 22,
            SamrDeleteGroup = 23,
            SamrRemoveMemberFromGroup = 24,
            SamrGetMembersInGroup = 25,
            SamrSetMemberAttributesOfGroup = 26,
            SamrOpenAlias = 27,
            SamrQueryInformationAlias = 28,
            SamrSetInformationAlias = 29,
            SamrDeleteAlias = 30,
            SamrAddMemberToAlias = 31,
            SamrRemoveMemberFromAlias = 32,
            SamrGetMembersInAlias = 33,
            SamrOpenUser = 34,
            SamrDeleteUser = 35,
            SamrQueryInformationUser = 36,
            SamrSetInformationUser = 37,
            SamrChangePasswordUser = 38,
            SamrGetGroupsForUser = 39,
            SamrQueryDisplayInformation = 40,
            SamrGetDisplayEnumerationIndex = 41,
            Opnum42NotUsedOnWire = 42,
            Opnum43NotUsedOnWire = 43,
            SamrGetUserDomainPasswordInformation = 44,
            SamrRemoveMemberFromForeignDomain = 45,
            SamrQueryInformationDomain2 = 46,
            SamrQueryInformationUser2 = 47,
            SamrQueryDisplayInformation2 = 48,
            SamrGetDisplayEnumerationIndex2 = 49,
            SamrCreateUser2InDomain = 50,
            SamrQueryDisplayInformation3 = 51,
            SamrAddMultipleMembersToAlias = 52,
            SamrRemoveMultipleMembersFromAlias = 53,
            SamrOemChangePasswordUser2 = 54,
            SamrUnicodeChangePasswordUser2 = 55,
            SamrGetDomainPasswordInformation = 56,
            SamrConnect2 = 57,
            SamrSetInformationUser2 = 58,
            Opnum59NotUsedOnWire = 59,
            Opnum60NotUsedOnWire = 60,
            Opnum61NotUsedOnWire = 61,
            SamrConnect4 = 62,
            Opnum63NotUsedOnWire = 63,
            SamrConnect5 = 64,
            SamrRidToSid = 65,
            SamrSetDSRMPassword = 66,
            SamrValidatePassword = 67,
            Opnum68NotUsedOnWire = 68,
            Opnum69NotUsedOnWire = 69,
            Opnum70NotUsedOnWire = 70,
            Opnum71NotUsedOnWire = 71,
            Opnum72NotUsedOnWire = 72,
            SamrUnicodeChangePasswordUser4 = 73,
            SamrValidateComputerAccountReuseAttempt = 74
        }

        /// <summary>
        /// SMB CMD
        /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4
        /// </summary>
        public enum SMB_CMD
        {
            NOTSET = int.MinValue,
            NEGOTIATE = 0,
            SESSION_SETUP = 1,
            LOGOFF = 2,
            TREE_CONNECT = 3,
            TREE_DISCONNECT = 4,
            CREATE = 5,
            CLOSE = 6,
            FLUSH = 7,
            READ = 8,
            WRITE = 9,
            LOCK = 10,
            IOCTL = 11,
            CANCEL = 12,
            ECHO = 13,
            QUERY_DIRECTORY = 14,
            CHANGE_NOTIFY = 15,
            QUERY_INFO = 16,
            SET_INFO = 17,
            OPLOCK_BREAK = 18
        }

        /// <summary>
        /// DCERPC Packet Types
        /// Thx: https://github.com/roo7break/impacket/blob/master/impacket/dcerpc/dcerpc.py#L30
        /// </summary>
        public enum PKT_DCERPC
        {
            NOTSET = int.MinValue,
            REQUEST = 0,
            PING = 1,
            RESPONSE = 2,
            FAULT = 3,
            WORKING = 4,
            NOCALL = 5,
            REJECT = 6,
            ACK = 7,
            CL_CANCEL = 8,
            FACK = 9,
            CANCELACK = 10,
            BIND = 11,
            BINDACK = 12,
            BINDNAK = 13,
            ALTERCTX = 14,
            ALTERCTX_R = 15,
            AUTH3 = 16,
            SHUTDOWN = 17,
            CO_CANCEL = 18,
            ORPHANED = 19
        }

        [Flags]
        public enum SMB2_FLAGS : uint
        {
            NOTSET = uint.MinValue,
            SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001,
            SMB2_FLAGS_ASYNC_COMMAND = 0x00000002,
            SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004,
            SMB2_FLAGS_SIGNED = 0x00000008,
            SMB2_FLAGS_DFS_OPERATIONS = 0x10000000,
            SMB2_FLAGS_REPLAY_OPERATION = 0x80000000
        }

        public enum SMB_Dialect
        {
            SMB2_DIALECT_002 = 0x0202,
            SMB2_DIALECT_21 = 0x0210,
            SMB2_DIALECT_30 = 0x0300,
            SMB2_DIALECT_302 = 0x0302, // #SMB 3.0.2
            SMB2_DIALECT_311 = 0x0311, // #SMB 3.1.1
            SMB2_DIALECT_WILDCARD = 0x02FF
        }

        /// <summary>
        /// Thx: https://github.com/mubix/ntds_decode/blob/master/attributes.h
        /// </summary>
        public enum ATTIds
        {
            [Description("accountNameHistory")]
            ATT_ACCOUNT_NAME_HISTORY = 591131,

            [Description("aCSAggregateTokenRatePerUser")]
            ATT_ACS_AGGREGATE_TOKEN_RATE_PER_USER = 590584,

            [Description("aCSAllocableRSVPBandwidth")]
            ATT_ACS_ALLOCABLE_RSVP_BANDWIDTH = 590590,

            [Description("aCSCacheTimeout")]
            ATT_ACS_CACHE_TIMEOUT = 590603,

            [Description("aCSDirection")]
            ATT_ACS_DIRECTION = 590581,

            [Description("aCSDSBMDeadTime")]
            ATT_ACS_DSBM_DEADTIME = 590602,

            [Description("aCSDSBMPriority")]
            ATT_ACS_DSBM_PRIORITY = 590600,

            [Description("aCSDSBMRefresh")]
            ATT_ACS_DSBM_REFRESH = 590601,

            [Description("aCSEnableACSService")]
            ATT_ACS_ENABLE_ACS_SERVICE = 590594,

            [Description("aCSEnableRSVPAccounting")]
            ATT_ACS_ENABLE_RSVP_ACCOUNTING = 590723,

            [Description("aCSEnableRSVPMessageLogging")]
            ATT_ACS_ENABLE_RSVP_MESSAGE_LOGGING = 590592,

            [Description("aCSEventLogLevel")]
            ATT_ACS_EVENT_LOG_LEVEL = 590593,

            [Description("aCSIdentityName")]
            ATT_ACS_IDENTITY_NAME = 590608,

            [Description("aCSMaxAggregatePeakRatePerUser")]
            ATT_ACS_MAX_AGGREGATE_PEAK_RATE_PER_USER = 590721,

            [Description("aCSMaxDurationPerFlow")]
            ATT_ACS_MAX_DURATION_PER_FLOW = 590585,

            [Description("aCSMaxNoOfAccountFiles")]
            ATT_ACS_MAX_NO_OF_ACCOUNT_FILES = 590725,

            [Description("aCSMaxNoOfLogFiles")]
            ATT_ACS_MAX_NO_OF_LOG_FILES = 590598,

            [Description("aCSMaxPeakBandwidth")]
            ATT_ACS_MAX_PEAK_BANDWIDTH = 590591,

            [Description("aCSMaxPeakBandwidthPerFlow")]
            ATT_ACS_MAX_PEAK_BANDWIDTH_PER_FLOW = 590583,

            [Description("aCSMaxSizeOfRSVPAccountFile")]
            ATT_ACS_MAX_SIZE_OF_RSVP_ACCOUNT_FILE = 590726,

            [Description("aCSMaxSizeOfRSVPLogFile")]
            ATT_ACS_MAX_SIZE_OF_RSVP_LOG_FILE = 590599,

            [Description("aCSMaxTokenBucketPerFlow")]
            ATT_ACS_MAX_TOKEN_BUCKET_PER_FLOW = 591137,

            [Description("aCSMaxTokenRatePerFlow")]
            ATT_ACS_MAX_TOKEN_RATE_PER_FLOW = 590582,

            [Description("aCSMaximumSDUSize")]
            ATT_ACS_MAXIMUM_SDU_SIZE = 591138,

            [Description("aCSMinimumDelayVariation")]
            ATT_ACS_MINIMUM_DELAY_VARIATION = 591141,

            [Description("aCSMinimumLatency")]
            ATT_ACS_MINIMUM_LATENCY = 591140,

            [Description("aCSMinimumPolicedSize")]
            ATT_ACS_MINIMUM_POLICED_SIZE = 591139,

            [Description("aCSNonReservedMaxSDUSize")]
            ATT_ACS_NON_RESERVED_MAX_SDU_SIZE = 591144,

            [Description("aCSNonReservedMinPolicedSize")]
            ATT_ACS_NON_RESERVED_MIN_POLICED_SIZE = 591145,

            [Description("aCSNonReservedPeakRate")]
            ATT_ACS_NON_RESERVED_PEAK_RATE = 591142,

            [Description("aCSNonReservedTokenSize")]
            ATT_ACS_NON_RESERVED_TOKEN_SIZE = 591143,

            [Description("aCSNonReservedTxLimit")]
            ATT_ACS_NON_RESERVED_TX_LIMIT = 590604,

            [Description("aCSNonReservedTxSize")]
            ATT_ACS_NON_RESERVED_TX_SIZE = 590722,

            [Description("aCSPermissionBits")]
            ATT_ACS_PERMISSION_BITS = 590589,

            [Description("aCSPolicyName")]
            ATT_ACS_POLICY_NAME = 590596,

            [Description("aCSPriority")]
            ATT_ACS_PRIORITY = 590588,

            [Description("aCSRSVPAccountFilesLocation")]
            ATT_ACS_RSVP_ACCOUNT_FILES_LOCATION = 590724,

            [Description("aCSRSVPLogFilesLocation")]
            ATT_ACS_RSVP_LOG_FILES_LOCATION = 590597,

            [Description("aCSServiceType")]
            ATT_ACS_SERVICE_TYPE = 590586,

            [Description("aCSTimeOfDay")]
            ATT_ACS_TIME_OF_DAY = 590580,

            [Description("aCSTotalNoOfFlows")]
            ATT_ACS_TOTAL_NO_OF_FLOWS = 590587,

            [Description("aCSServerList")]
            ATT_ACS_SERVER_LIST = 591136,

            [Description("additionalTrustedServiceNames")]
            ATT_ADDITIONAL_TRUSTED_SERVICE_NAMES = 590713,

            [Description("adminContextMenu")]
            ATT_ADMIN_CONTEXT_MENU = 590438,

            [Description("adminDescription")]
            ATT_ADMIN_DESCRIPTION = 131298,

            [Description("adminPropertyPages")]
            ATT_ADMIN_PROPERTY_PAGES = 590386,

            [Description("appSchemaVersion")]
            ATT_APP_SCHEMA_VERSION = 590672,

            [Description("applicationName")]
            ATT_APPLICATION_NAME = 590042,

            [Description("appliesTo")]
            ATT_APPLIES_TO = 590165,

            [Description("assetNumber")]
            ATT_ASSET_NUMBER = 590107,

            [Description("assistant")]
            ATT_ASSISTANT = 590476,

            [Description("assocNTAccount")]
            ATT_ASSOC_NT_ACCOUNT = 591037,

            [Description("attributeDisplayNames")]
            ATT_ATTRIBUTE_DISPLAY_NAMES = 590572,

            [Description("birthLocation")]
            ATT_BIRTH_LOCATION = 590156,

            [Description("bridgeheadTransportList")]
            ATT_BRIDGEHEAD_TRANSPORT_LIST = 590643,

            [Description("builtinCreationTime")]
            ATT_BUILTIN_CREATION_TIME = 589837,

            [Description("builtinModifiedCount")]
            ATT_BUILTIN_MODIFIED_COUNT = 589838,

            [Description("businessCategory")]
            ATT_BUSINESS_CATEGORY = 15,

            [Description("bytesPerMinute")]
            ATT_BYTES_PER_MINUTE = 590108,

            [Description("cACertificate")]
            ATT_CA_CERTIFICATE = 37,

            [Description("cACertificateDN")]
            ATT_CA_CERTIFICATE_DN = 590521,

            [Description("cAConnect")]
            ATT_CA_CONNECT = 590511,

            [Description("cAUsages")]
            ATT_CA_USAGES = 590514,

            [Description("cAWEBURL")]
            ATT_CA_WEB_URL = 590512,

            [Description("canUpgradeScript")]
            ATT_CAN_UPGRADE_SCRIPT = 590639,

            [Description("catalogs")]
            ATT_CATALOGS = 590499,

            [Description("categories")]
            ATT_CATEGORIES = 590496,

            [Description("categoryId")]
            ATT_CATEGORY_ID = 590146,

            [Description("certificateAuthorityObject")]
            ATT_CERTIFICATE_AUTHORITY_OBJECT = 590508,

            [Description("certificateTemplates")]
            ATT_CERTIFICATE_TEMPLATES = 590647,

            [Description("classDisplayName")]
            ATT_CLASS_DISPLAY_NAME = 590434,

            [Description("cOMClassID")]
            ATT_COM_CLASSID = 589843,

            [Description("cOMCLSID")]
            ATT_COM_CLSID = 590073,

            [Description("cOMInterfaceID")]
            ATT_COM_INTERFACEID = 589844,

            [Description("cOMOtherProgId")]
            ATT_COM_OTHER_PROG_ID = 590077,

            [Description("cOMProgID")]
            ATT_COM_PROGID = 589845,

            [Description("cOMTreatAsClassId")]
            ATT_COM_TREAT_AS_CLASS_ID = 590075,

            [Description("cOMTypelibId")]
            ATT_COM_TYPELIB_ID = 590078,

            [Description("cOMUniqueLIBID")]
            ATT_COM_UNIQUE_LIBID = 590074,

            [Description("contentIndexingAllowed")]
            ATT_CONTENT_INDEXING_ALLOWED = 589848,

            [Description("contextMenu")]
            ATT_CONTEXT_MENU = 590323,

            [Description("controlAccessRights")]
            ATT_CONTROL_ACCESS_RIGHTS = 590024,

            [Description("createDialog")]
            ATT_CREATE_DIALOG = 590634,

            [Description("createWizardExt")]
            ATT_CREATE_WIZARD_EXT = 590636,

            [Description("creationWizard")]
            ATT_CREATION_WIZARD = 590322,

            [Description("creator")]
            ATT_CREATOR = 590503,

            [Description("cRLObject")]
            ATT_CRL_OBJECT = 590513,

            [Description("currMachineId")]
            ATT_CURR_MACHINE_ID = 590161,

            [Description("currentLocation")]
            ATT_CURRENT_LOCATION = 590159,

            [Description("currentParentCA")]
            ATT_CURRENT_PARENT_CA = 590520,

            [Description("defaultClassStore")]
            ATT_DEFAULT_CLASS_STORE = 590037,

            [Description("defaultGroup")]
            ATT_DEFAULT_GROUP = 590304,

            [Description("defaultLocalPolicyObject")]
            ATT_DEFAULT_LOCAL_POLICY_OBJECT = 589881,

            [Description("defaultPriority")]
            ATT_DEFAULT_PRIORITY = 590056,

            [Description("desktopProfile")]
            ATT_DESKTOP_PROFILE = 590170,

            [Description("destinationIndicator")]
            ATT_DESTINATION_INDICATOR = 27,

            [Description("dhcpClasses")]
            ATT_DHCP_CLASSES = 590539,

            [Description("dhcpFlags")]
            ATT_DHCP_FLAGS = 590524,

            [Description("dhcpIdentification")]
            ATT_DHCP_IDENTIFICATION = 590525,

            [Description("dhcpMask")]
            ATT_DHCP_MASK = 590530,

            [Description("dhcpMaxKey")]
            ATT_DHCP_MAXKEY = 590543,

            [Description("dhcpObjDescription")]
            ATT_DHCP_OBJ_DESCRIPTION = 590527,

            [Description("dhcpObjName")]
            ATT_DHCP_OBJ_NAME = 590526,

            [Description("dhcpOptions")]
            ATT_DHCP_OPTIONS = 590538,

            [Description("dhcpProperties")]
            ATT_DHCP_PROPERTIES = 590542,

            [Description("dhcpRanges")]
            ATT_DHCP_RANGES = 590531,

            [Description("dhcpReservations")]
            ATT_DHCP_RESERVATIONS = 590533,

            [Description("dhcpSites")]
            ATT_DHCP_SITES = 590532,

            [Description("dhcpState")]
            ATT_DHCP_STATE = 590541,

            [Description("dhcpSubnets")]
            ATT_DHCP_SUBNETS = 590529,

            [Description("dhcpType")]
            ATT_DHCP_TYPE = 590523,

            [Description("dhcpUniqueKey")]
            ATT_DHCP_UNIQUE_KEY = 590522,

            [Description("dhcpUpdateTime")]
            ATT_DHCP_UPDATE_TIME = 590544,

            [Description("division")]
            ATT_DIVISION = 590085,

            [Description("dmdName")]
            ATT_DMD_NAME = 131670,

            [Description("dnsAllowDynamic")]
            ATT_DNS_ALLOW_DYNAMIC = 590202,

            [Description("dnsAllowXFR")]
            ATT_DNS_ALLOW_XFR = 590203,

            [Description("dnsNotifySecondaries")]
            ATT_DNS_NOTIFY_SECONDARIES = 590205,

            [Description("dNSProperty")]
            ATT_DNS_PROPERTY = 591130,

            [Description("dnsRecord")]
            ATT_DNS_RECORD = 590206,

            [Description("dnsSecureSecondaries")]
            ATT_DNS_SECURE_SECONDARIES = 590204,

            [Description("dNSTombstoned")]
            ATT_DNS_TOMBSTONED = 591238,

            [Description("domainCAs")]
            ATT_DOMAIN_CERTIFICATE_AUTHORITIES = 590492,

            [Description("domainID")]
            ATT_DOMAIN_ID = 590510,

            [Description("domainIdentifier")]
            ATT_DOMAIN_IDENTIFIER = 590579,

            [Description("domainPolicyObject")]
            ATT_DOMAIN_POLICY_OBJECT = 589856,

            [Description("domainPolicyReference")]
            ATT_DOMAIN_POLICY_REFERENCE = 590246,

            [Description("domainWidePolicy")]
            ATT_DOMAIN_WIDE_POLICY = 590245,

            [Description("driverName")]
            ATT_DRIVER_NAME = 590053,

            [Description("driverVersion")]
            ATT_DRIVER_VERSION = 590100,

            [Description("dSUIAdminMaximum")]
            ATT_DS_UI_ADMIN_MAXIMUM = 591168,

            [Description("dSUIAdminNotification")]
            ATT_DS_UI_ADMIN_NOTIFICATION = 591167,

            [Description("dSUIShellMaximum")]
            ATT_DS_UI_SHELL_MAXIMUM = 591169,

            [Description("dynamicLDAPServer")]
            ATT_DYNAMIC_LDAP_SERVER = 590361,

            [Description("employeeID")]
            ATT_EMPLOYEE_ID = 589859,

            [Description("enrollmentProviders")]
            ATT_ENROLLMENT_PROVIDERS = 590649,

            [Description("extensionName")]
            ATT_EXTENSION_NAME = 131299,

            [Description("fileExtPriority")]
            ATT_FILE_EXT_PRIORITY = 590640,

            [Description("flags")]
            ATT_FLAGS = 589862,

            [Description("foreignIdentifier")]
            ATT_FOREIGN_IDENTIFIER = 590180,

            [Description("friendlyNames")]
            ATT_FRIENDLY_NAMES = 590506,

            [Description("frsComputerReference")]
            ATT_FRS_COMPUTER_REFERENCE = 590693,

            [Description("frsComputerReferenceBL")]
            ATT_FRS_COMPUTER_REFERENCE_BL = 590694,

            [Description("fRSControlDataCreation")]
            ATT_FRS_CONTROL_DATA_CREATION = 590695,

            [Description("fRSControlInboundBacklog")]
            ATT_FRS_CONTROL_INBOUND_BACKLOG = 590696,

            [Description("fRSControlOutboundBacklog")]
            ATT_FRS_CONTROL_OUTBOUND_BACKLOG = 590697,

            [Description("fRSDirectoryFilter")]
            ATT_FRS_DIRECTORY_FILTER = 590308,

            [Description("fRSDSPoll")]
            ATT_FRS_DS_POLL = 590314,

            [Description("fRSExtensions")]
            ATT_FRS_EXTENSIONS = 590360,

            [Description("fRSFaultCondition")]
            ATT_FRS_FAULT_CONDITION = 590315,

            [Description("fRSFileFilter")]
            ATT_FRS_FILE_FILTER = 590307,

            [Description("fRSFlags")]
            ATT_FRS_FLAGS = 590698,

            [Description("fRSLevelLimit")]
            ATT_FRS_LEVEL_LIMIT = 590358,

            [Description("fRSMemberReference")]
            ATT_FRS_MEMBER_REFERENCE = 590699,

            [Description("fRSMemberReferenceBL")]
            ATT_FRS_MEMBER_REFERENCE_BL = 590700,

            [Description("fRSPartnerAuthLevel")]
            ATT_FRS_PARTNER_AUTH_LEVEL = 590701,

            [Description("fRSPrimaryMember")]
            ATT_FRS_PRIMARY_MEMBER = 590702,

            [Description("fRSReplicaSetGUID")]
            ATT_FRS_REPLICA_SET_GUID = 590357,

            [Description("fRSReplicaSetType")]
            ATT_FRS_REPLICA_SET_TYPE = 589855,

            [Description("fRSRootPath")]
            ATT_FRS_ROOT_PATH = 590311,

            [Description("fRSRootSecurity")]
            ATT_FRS_ROOT_SECURITY = 590359,

            [Description("fRSServiceCommand")]
            ATT_FRS_SERVICE_COMMAND = 590324,

            [Description("fRSServiceCommandStatus")]
            ATT_FRS_SERVICE_COMMAND_STATUS = 590703,

            [Description("fRSStagingPath")]
            ATT_FRS_STAGING_PATH = 590312,

            [Description("fRSTimeLastCommand")]
            ATT_FRS_TIME_LAST_COMMAND = 590704,

            [Description("fRSTimeLastConfigChange")]
            ATT_FRS_TIME_LAST_CONFIG_CHANGE = 590705,

            [Description("fRSUpdateTimeout")]
            ATT_FRS_UPDATE_TIMEOUT = 590309,

            [Description("fRSVersion")]
            ATT_FRS_VERSION = 590706,

            [Description("fRSVersionGUID")]
            ATT_FRS_VERSION_GUID = 589867,

            [Description("fRSWorkingPath")]
            ATT_FRS_WORKING_PATH = 590310,

            [Description("generatedConnection")]
            ATT_GENERATED_CONNECTION = 589865,

            [Description("generationQualifier")]
            ATT_GENERATION_QUALIFIER = 44,

            [Description("gPLink")]
            ATT_GP_LINK = 590715,

            [Description("gPOptions")]
            ATT_GP_OPTIONS = 590716,

            [Description("gPCFileSysPath")]
            ATT_GPC_FILE_SYS_PATH = 590718,

            [Description("gPCFunctionalityVersion")]
            ATT_GPC_FUNCTIONALITY_VERSION = 590717,

            [Description("gPCMachineExtensionNames")]
            ATT_GPC_MACHINE_EXTENSION_NAMES = 591172,

            [Description("gPCUserExtensionNames")]
            ATT_GPC_USER_EXTENSION_NAMES = 591173,

            [Description("groupAttributes")]
            ATT_GROUP_ATTRIBUTES = 589976,

            [Description("groupMembershipSAM")]
            ATT_GROUP_MEMBERSHIP_SAM = 589990,

            [Description("groupPriority")]
            ATT_GROUP_PRIORITY = 590169,

            [Description("groupsToIgnore")]
            ATT_GROUPS_TO_IGNORE = 590168,

            [Description("iconPath")]
            ATT_ICON_PATH = 590043,

            [Description("implementedCategories")]
            ATT_IMPLEMENTED_CATEGORIES = 590144,

            [Description("indexedScopes")]
            ATT_INDEXEDSCOPES = 590505,

            [Description("installUiLevel")]
            ATT_INSTALL_UI_LEVEL = 590671,

            [Description("internationalISDNNumber")]
            ATT_INTERNATIONAL_ISDN_NUMBER = 25,

            [Description("ipsecData")]
            ATT_IPSEC_DATA = 590447,

            [Description("ipsecDataType")]
            ATT_IPSEC_DATA_TYPE = 590446,

            [Description("ipsecFilterReference")]
            ATT_IPSEC_FILTER_REFERENCE = 590453,

            [Description("ipsecID")]
            ATT_IPSEC_ID = 590445,

            [Description("ipsecISAKMPReference")]
            ATT_IPSEC_ISAKMP_REFERENCE = 590450,

            [Description("ipsecName")]
            ATT_IPSEC_NAME = 590444,

            [Description("iPSECNegotiationPolicyAction")]
            ATT_IPSEC_NEGOTIATION_POLICY_ACTION = 590712,

            [Description("ipsecNegotiationPolicyReference")]
            ATT_IPSEC_NEGOTIATION_POLICY_REFERENCE = 590452,

            [Description("iPSECNegotiationPolicyType")]
            ATT_IPSEC_NEGOTIATION_POLICY_TYPE = 590711,

            [Description("ipsecNFAReference")]
            ATT_IPSEC_NFA_REFERENCE = 590451,

            [Description("ipsecOwnersReference")]
            ATT_IPSEC_OWNERS_REFERENCE = 590448,

            [Description("ipsecPolicyReference")]
            ATT_IPSEC_POLICY_REFERENCE = 590341,

            [Description("isEphemeral")]
            ATT_IS_EPHEMERAL = 591036,

            [Description("isPrivilegeHolder")]
            ATT_IS_PRIVILEGE_HOLDER = 590462,

            [Description("knowledgeInformation")]
            ATT_KNOWLEDGE_INFORMATION = 2,

            [Description("lastBackupRestorationTime")]
            ATT_LAST_BACKUP_RESTORATION_TIME = 590343,

            [Description("lastContentIndexed")]
            ATT_LAST_CONTENT_INDEXED = 589874,

            [Description("lastUpdateSequence")]
            ATT_LAST_UPDATE_SEQUENCE = 590154,

            [Description("linkTrackSecret")]
            ATT_LINK_TRACK_SECRET = 590093,

            [Description("localPolicyReference")]
            ATT_LOCAL_POLICY_REFERENCE = 590281,

            [Description("localizedDescription")]
            ATT_LOCALIZED_DESCRIPTION = 590641,

            [Description("localizationDisplayId")]
            ATT_LOCALIZATION_DISPLAY_ID = 591177,

            [Description("location")]
            ATT_LOCATION = 590046,

            [Description("logonWorkstation")]
            ATT_LOGON_WORKSTATION = 589889,

            [Description("lSACreationTime")]
            ATT_LSA_CREATION_TIME = 589890,

            [Description("lSAModifiedCount")]
            ATT_LSA_MODIFIED_COUNT = 589891,

            [Description("machineArchitecture")]
            ATT_MACHINE_ARCHITECTURE = 589892,

            [Description("machinePasswordChangeInterval")]
            ATT_MACHINE_PASSWORD_CHANGE_INTERVAL = 590344,

            [Description("machineWidePolicy")]
            ATT_MACHINE_WIDE_POLICY = 590283,

            [Description("managedObjects")]
            ATT_MANAGED_OBJECTS = 590478,

            [Description("manager")]
            ATT_MANAGER = 1376266,

            [Description("marshalledInterface")]
            ATT_MARSHALLED_INTERFACE = 589896,

            [Description("maxStorage")]
            ATT_MAX_STORAGE = 589900,

            [Description("meetingAdvertiseScope")]
            ATT_MEETINGADVERTISESCOPE = 590406,

            [Description("meetingApplication")]
            ATT_MEETINGAPPLICATION = 590397,

            [Description("meetingBandwidth")]
            ATT_MEETINGBANDWIDTH = 590413,

            [Description("meetingBlob")]
            ATT_MEETINGBLOB = 590414,

            [Description("meetingContactInfo")]
            ATT_MEETINGCONTACTINFO = 590402,

            [Description("meetingDescription")]
            ATT_MEETINGDESCRIPTION = 590391,

            [Description("meetingEndTime")]
            ATT_MEETINGENDTIME = 590412,

            [Description("meetingID")]
            ATT_MEETINGID = 590389,

            [Description("meetingIP")]
            ATT_MEETINGIP = 590404,

            [Description("meetingIsEncrypted")]
            ATT_MEETINGISENCRYPTED = 590409,

            [Description("meetingKeyword")]
            ATT_MEETINGKEYWORD = 590392,

            [Description("meetingLanguage")]
            ATT_MEETINGLANGUAGE = 590398,

            [Description("meetingLocation")]
            ATT_MEETINGLOCATION = 590393,

            [Description("meetingMaxParticipants")]
            ATT_MEETINGMAXPARTICIPANTS = 590400,

            [Description("meetingName")]
            ATT_MEETINGNAME = 590390,

            [Description("meetingOriginator")]
            ATT_MEETINGORIGINATOR = 590401,

            [Description("meetingOwner")]
            ATT_MEETINGOWNER = 590403,

            [Description("meetingProtocol")]
            ATT_MEETINGPROTOCOL = 590394,

            [Description("meetingRating")]
            ATT_MEETINGRATING = 590408,

            [Description("meetingRecurrence")]
            ATT_MEETINGRECURRENCE = 590410,

            [Description("meetingScope")]
            ATT_MEETINGSCOPE = 590405,

            [Description("meetingStartTime")]
            ATT_MEETINGSTARTTIME = 590411,

            [Description("meetingType")]
            ATT_MEETINGTYPE = 590395,

            [Description("meetingURL")]
            ATT_MEETINGURL = 590407,

            [Description("mhsORAddress")]
            ATT_MHS_OR_ADDRESS = 590474,

            [Description("moniker")]
            ATT_MONIKER = 589906,

            [Description("monikerDisplayName")]
            ATT_MONIKER_DISPLAY_NAME = 589907,

            [Description("moveTreeState")]
            ATT_MOVE_TREE_STATE = 591129,

            [Description("mS-DS-ConsistencyGuid")]
            ATT_MS_DS_CONSISTENCY_GUID = 591184,

            [Description("mS-DS-ConsistencyChildCount")]
            ATT_MS_DS_CONSISTENCY_CHILD_COUNT = 591185,

            [Description("msRRASAttribute")]
            ATT_MS_RRAS_ATTRIBUTE = 590708,

            [Description("msRRASVendorAttributeEntry")]
            ATT_MS_RRAS_VENDOR_ATTRIBUTE_ENTRY = 590707,

            [Description("mS-SQL-Name")]
            ATT_MS_SQL_NAME = 591187,

            [Description("mS-SQL-RegisteredOwner")]
            ATT_MS_SQL_REGISTEREDOWNER = 591188,

            [Description("mS-SQL-Contact")]
            ATT_MS_SQL_CONTACT = 591189,

            [Description("mS-SQL-Location")]
            ATT_MS_SQL_LOCATION = 591190,

            [Description("mS-SQL-Memory")]
            ATT_MS_SQL_MEMORY = 591191,

            [Description("mS-SQL-Build")]
            ATT_MS_SQL_BUILD = 591192,

            [Description("mS-SQL-ServiceAccount")]
            ATT_MS_SQL_SERVICEACCOUNT = 591193,

            [Description("mS-SQL-CharacterSet")]
            ATT_MS_SQL_CHARACTERSET = 591194,

            [Description("mS-SQL-SortOrder")]
            ATT_MS_SQL_SORTORDER = 591195,

            [Description("mS-SQL-UnicodeSortOrder")]
            ATT_MS_SQL_UNICODESORTORDER = 591196,

            [Description("mS-SQL-Clustered")]
            ATT_MS_SQL_CLUSTERED = 591197,

            [Description("mS-SQL-NamedPipe")]
            ATT_MS_SQL_NAMEDPIPE = 591198,

            [Description("mS-SQL-MultiProtocol")]
            ATT_MS_SQL_MULTIPROTOCOL = 591199,

            [Description("mS-SQL-SPX")]
            ATT_MS_SQL_SPX = 591200,

            [Description("mS-SQL-TCPIP")]
            ATT_MS_SQL_TCPIP = 591201,

            [Description("mS-SQL-AppleTalk")]
            ATT_MS_SQL_APPLETALK = 591202,

            [Description("mS-SQL-Vines")]
            ATT_MS_SQL_VINES = 591203,

            [Description("mS-SQL-Status")]
            ATT_MS_SQL_STATUS = 591204,

            [Description("mS-SQL-LastUpdatedDate")]
            ATT_MS_SQL_LASTUPDATEDDATE = 591205,

            [Description("mS-SQL-InformationURL")]
            ATT_MS_SQL_INFORMATIONURL = 591206,

            [Description("mS-SQL-ConnectionURL")]
            ATT_MS_SQL_CONNECTIONURL = 591207,

            [Description("mS-SQL-PublicationURL")]
            ATT_MS_SQL_PUBLICATIONURL = 591208,

            [Description("mS-SQL-GPSLatitude")]
            ATT_MS_SQL_GPSLATITUDE = 591209,

            [Description("mS-SQL-GPSLongitude")]
            ATT_MS_SQL_GPSLONGITUDE = 591210,

            [Description("mS-SQL-GPSHeight")]
            ATT_MS_SQL_GPSHEIGHT = 591211,

            [Description("mS-SQL-Version")]
            ATT_MS_SQL_VERSION = 591212,

            [Description("mS-SQL-Language")]
            ATT_MS_SQL_LANGUAGE = 591213,

            [Description("mS-SQL-Description")]
            ATT_MS_SQL_DESCRIPTION = 591214,

            [Description("mS-SQL-Type")]
            ATT_MS_SQL_TYPE = 591215,

            [Description("mS-SQL-InformationDirectory")]
            ATT_MS_SQL_INFORMATIONDIRECTORY = 591216,

            [Description("mS-SQL-Database")]
            ATT_MS_SQL_DATABASE = 591217,

            [Description("mS-SQL-AllowAnonymousSubscription")]
            ATT_MS_SQL_ALLOWANONYMOUSSUBSCRIPTION = 591218,

            [Description("mS-SQL-Alias")]
            ATT_MS_SQL_ALIAS = 591219,

            [Description("mS-SQL-Size")]
            ATT_MS_SQL_SIZE = 591220,

            [Description("mS-SQL-CreationDate")]
            ATT_MS_SQL_CREATIONDATE = 591221,

            [Description("mS-SQL-LastBackupDate")]
            ATT_MS_SQL_LASTBACKUPDATE = 591222,

            [Description("mS-SQL-LastDiagnosticDate")]
            ATT_MS_SQL_LASTDIAGNOSTICDATE = 591223,

            [Description("mS-SQL-Applications")]
            ATT_MS_SQL_APPLICATIONS = 591224,

            [Description("mS-SQL-Keywords")]
            ATT_MS_SQL_KEYWORDS = 591225,

            [Description("mS-SQL-Publisher")]
            ATT_MS_SQL_PUBLISHER = 591226,

            [Description("mS-SQL-AllowKnownPullSubscription")]
            ATT_MS_SQL_ALLOWKNOWNPULLSUBSCRIPTION = 591227,

            [Description("mS-SQL-AllowImmediateUpdatingSubscription")]
            ATT_MS_SQL_ALLOWIMMEDIATEUPDATINGSUBSCRIPTION = 591228,

            [Description("mS-SQL-AllowQueuedUpdatingSubscription")]
            ATT_MS_SQL_ALLOWQUEUEDUPDATINGSUBSCRIPTION = 591229,

            [Description("mS-SQL-AllowSnapshotFilesFTPDownloading")]
            ATT_MS_SQL_ALLOWSNAPSHOTFILESFTPDOWNLOADING = 591230,

            [Description("mS-SQL-ThirdParty")]
            ATT_MS_SQL_THIRDPARTY = 591231,

            [Description("mscopeId")]
            ATT_MSCOPE_ID = 590540,

            [Description("msiFileList")]
            ATT_MSI_FILE_LIST = 590495,

            [Description("msiScript")]
            ATT_MSI_SCRIPT = 590638,

            [Description("msiScriptName")]
            ATT_MSI_SCRIPT_NAME = 590669,

            [Description("msiScriptPath")]
            ATT_MSI_SCRIPT_PATH = 589839,

            [Description("msiScriptSize")]
            ATT_MSI_SCRIPT_SIZE = 590670,

            [Description("mSMQAuthenticate")]
            ATT_MSMQ_AUTHENTICATE = 590747,

            [Description("mSMQBasePriority")]
            ATT_MSMQ_BASE_PRIORITY = 590744,

            [Description("mSMQComputerType")]
            ATT_MSMQ_COMPUTER_TYPE = 590757,

            [Description("mSMQComputerTypeEx")]
            ATT_MSMQ_COMPUTER_TYPE_EX = 591241,

            [Description("mSMQCost")]
            ATT_MSMQ_COST = 590770,

            [Description("mSMQCSPName")]
            ATT_MSMQ_CSP_NAME = 590764,

            [Description("mSMQDependentClientService")]
            ATT_MSMQ_DEPENDENT_CLIENT_SERVICE = 591063,

            [Description("mSMQDependentClientServices")]
            ATT_MSMQ_DEPENDENT_CLIENT_SERVICES = 591050,

            [Description("mSMQDigests")]
            ATT_MSMQ_DIGESTS = 590772,

            [Description("mSMQDigestsMig")]
            ATT_MSMQ_DIGESTS_MIG = 590790,

            [Description("mSMQDsService")]
            ATT_MSMQ_DS_SERVICE = 591062,

            [Description("mSMQDsServices")]
            ATT_MSMQ_DS_SERVICES = 591052,

            [Description("mSMQEncryptKey")]
            ATT_MSMQ_ENCRYPT_KEY = 590760,

            [Description("mSMQForeign")]
            ATT_MSMQ_FOREIGN = 590758,

            [Description("mSMQInRoutingServers")]
            ATT_MSMQ_IN_ROUTING_SERVERS = 590753,

            [Description("mSMQInterval1")]
            ATT_MSMQ_INTERVAL1 = 591132,

            [Description("mSMQInterval2")]
            ATT_MSMQ_INTERVAL2 = 591133,

            [Description("mSMQJournal")]
            ATT_MSMQ_JOURNAL = 590742,

            [Description("mSMQJournalQuota")]
            ATT_MSMQ_JOURNAL_QUOTA = 590745,

            [Description("mSMQLabel")]
            ATT_MSMQ_LABEL = 590746,

            [Description("mSMQLabelEx")]
            ATT_MSMQ_LABEL_EX = 591239,

            [Description("mSMQLongLived")]
            ATT_MSMQ_LONG_LIVED = 590765,

            [Description("mSMQMigrated")]
            ATT_MSMQ_MIGRATED = 590776,

            [Description("mSMQNameStyle")]
            ATT_MSMQ_NAME_STYLE = 590763,

            [Description("mSMQNt4Flags")]
            ATT_MSMQ_NT4_FLAGS = 590788,

            [Description("mSMQNt4Stub")]
            ATT_MSMQ_NT4_STUB = 590784,

            [Description("mSMQOSType")]
            ATT_MSMQ_OS_TYPE = 590759,

            [Description("mSMQOutRoutingServers")]
            ATT_MSMQ_OUT_ROUTING_SERVERS = 590752,

            [Description("mSMQPrevSiteGates")]
            ATT_MSMQ_PREV_SITE_GATES = 591049,

            [Description("mSMQPrivacyLevel")]
            ATT_MSMQ_PRIVACY_LEVEL = 590748,

            [Description("mSMQQMID")]
            ATT_MSMQ_QM_ID = 590775,

            [Description("mSMQQueueJournalQuota")]
            ATT_MSMQ_QUEUE_JOURNAL_QUOTA = 590787,

            [Description("mSMQQueueNameExt")]
            ATT_MSMQ_QUEUE_NAME_EXT = 591067,

            [Description("mSMQQueueQuota")]
            ATT_MSMQ_QUEUE_QUOTA = 590786,

            [Description("mSMQQueueType")]
            ATT_MSMQ_QUEUE_TYPE = 590741,

            [Description("mSMQQuota")]
            ATT_MSMQ_QUOTA = 590743,

            [Description("mSMQRoutingService")]
            ATT_MSMQ_ROUTING_SERVICE = 591061,

            [Description("mSMQRoutingServices")]
            ATT_MSMQ_ROUTING_SERVICES = 591051,

            [Description("mSMQServiceType")]
            ATT_MSMQ_SERVICE_TYPE = 590754,

            [Description("mSMQServices")]
            ATT_MSMQ_SERVICES = 590774,

            [Description("mSMQSignKey")]
            ATT_MSMQ_SIGN_KEY = 590761,

            [Description("mSMQSite1")]
            ATT_MSMQ_SITE_1 = 590767,

            [Description("mSMQSite2")]
            ATT_MSMQ_SITE_2 = 590768,

            [Description("mSMQSiteForeign")]
            ATT_MSMQ_SITE_FOREIGN = 590785,

            [Description("mSMQSiteGates")]
            ATT_MSMQ_SITE_GATES = 590769,

            [Description("mSMQSiteGatesMig")]
            ATT_MSMQ_SITE_GATES_MIG = 591134,

            [Description("mSMQSiteID")]
            ATT_MSMQ_SITE_ID = 590777,

            [Description("mSMQSiteName")]
            ATT_MSMQ_SITE_NAME = 590789,

            [Description("mSMQSiteNameEx")]
            ATT_MSMQ_SITE_NAME_EX = 591240,

            [Description("mSMQSites")]
            ATT_MSMQ_SITES = 590751,

            [Description("mSMQTransactional")]
            ATT_MSMQ_TRANSACTIONAL = 590750,

            [Description("mSMQVersion")]
            ATT_MSMQ_VERSION = 590766,

            [Description("msNPCalledStationID")]
            ATT_MSNPCALLEDSTATIONID = 590947,

            [Description("nameServiceFlags")]
            ATT_NAME_SERVICE_FLAGS = 590577,

            [Description("netbootAllowNewClients")]
            ATT_NETBOOT_ALLOW_NEW_CLIENTS = 590673,

            [Description("netbootAnswerOnlyValidClients")]
            ATT_NETBOOT_ANSWER_ONLY_VALID_CLIENTS = 590678,

            [Description("netbootAnswerRequests")]
            ATT_NETBOOT_ANSWER_REQUESTS = 590677,

            [Description("netbootCurrentClientCount")]
            ATT_NETBOOT_CURRENT_CLIENT_COUNT = 590676,

            [Description("netbootGUID")]
            ATT_NETBOOT_GUID = 590183,

            [Description("netbootInitialization")]
            ATT_NETBOOT_INITIALIZATION = 590182,

            [Description("netbootIntelliMirrorOSes")]
            ATT_NETBOOT_INTELLIMIRROR_OSES = 590681,

            [Description("netbootLimitClients")]
            ATT_NETBOOT_LIMIT_CLIENTS = 590674,

            [Description("netbootLocallyInstalledOSes")]
            ATT_NETBOOT_LOCALLY_INSTALLED_OSES = 590683,

            [Description("netbootMachineFilePath")]
            ATT_NETBOOT_MACHINE_FILE_PATH = 590185,

            [Description("netbootMaxClients")]
            ATT_NETBOOT_MAX_CLIENTS = 590675,

            [Description("netbootMirrorDataFile")]
            ATT_NETBOOT_MIRROR_DATA_FILE = 591065,

            [Description("netbootNewMachineNamingPolicy")]
            ATT_NETBOOT_NEW_MACHINE_NAMING_POLICY = 590679,

            [Description("netbootNewMachineOU")]
            ATT_NETBOOT_NEW_MACHINE_OU = 590680,

            [Description("netbootServer")]
            ATT_NETBOOT_SERVER = 590684,

            [Description("netbootSIFFile")]
            ATT_NETBOOT_SIF_FILE = 591064,

            [Description("netbootTools")]
            ATT_NETBOOT_TOOLS = 590682,

            [Description("nextLevelStore")]
            ATT_NEXT_LEVEL_STORE = 590038,

            [Description("nonSecurityMember")]
            ATT_NON_SECURITY_MEMBER = 590354,

            [Description("nonSecurityMemberBL")]
            ATT_NON_SECURITY_MEMBER_BL = 590355,

            [Description("notificationList")]
            ATT_NOTIFICATION_LIST = 590127,

            [Description("nTGroupMembers")]
            ATT_NT_GROUP_MEMBERS = 589913,

            [Description("objectCount")]
            ATT_OBJECT_COUNT = 590330,

            [Description("oMTGuid")]
            ATT_OMT_GUID = 590329,

            [Description("oMTIndxGuid")]
            ATT_OMT_INDX_GUID = 590157,

            [Description("operatingSystemHotfix")]
            ATT_OPERATING_SYSTEM_HOTFIX = 590239,

            [Description("optionDescription")]
            ATT_OPTION_DESCRIPTION = 590536,

            [Description("optionsLocation")]
            ATT_OPTIONS_LOCATION = 590537,

            [Description("originalDisplayTable")]
            ATT_ORIGINAL_DISPLAY_TABLE = 131517,

            [Description("originalDisplayTableMSDOS")]
            ATT_ORIGINAL_DISPLAY_TABLE_MSDOS = 131286,

            [Description("otherLoginWorkstations")]
            ATT_OTHER_LOGIN_WORKSTATIONS = 589915,

            [Description("otherMailbox")]
            ATT_OTHER_MAILBOX = 590475,

            [Description("middleName")]
            ATT_OTHER_NAME = 1441826,

            [Description("packageFlags")]
            ATT_PACKAGE_FLAGS = 590151,

            [Description("packageName")]
            ATT_PACKAGE_NAME = 590150,

            [Description("packageType")]
            ATT_PACKAGE_TYPE = 590148,

            [Description("parentCA")]
            ATT_PARENT_CA = 590381,

            [Description("parentCACertificateChain")]
            ATT_PARENT_CA_CERTIFICATE_CHAIN = 590509,

            [Description("pekKeyChangeInterval")]
            ATT_PEK_KEY_CHANGE_INTERVAL = 590690,

            [Description("pendingCACertificates")]
            ATT_PENDING_CA_CERTIFICATES = 590517,

            [Description("pendingParentCA")]
            ATT_PENDING_PARENT_CA = 590519,

            [Description("perMsgDialogDisplayTable")]
            ATT_PER_MSG_DIALOG_DISPLAY_TABLE = 131397,

            [Description("perRecipDialogDisplayTable")]
            ATT_PER_RECIP_DIALOG_DISPLAY_TABLE = 131398,

            [Description("personalTitle")]
            ATT_PERSONAL_TITLE = 131687,

            [Description("homePhone")]
            ATT_PHONE_HOME_PRIMARY = 1376276,

            [Description("otherIpPhone")]
            ATT_PHONE_IP_OTHER = 590546,

            [Description("primaryInternationalISDNNumber")]
            ATT_PHONE_ISDN_PRIMARY = 590473,

            [Description("physicalLocationObject")]
            ATT_PHYSICAL_LOCATION_OBJECT = 590338,

            [Description("pKICriticalExtensions")]
            ATT_PKI_CRITICAL_EXTENSIONS = 591154,

            [Description("pKIDefaultCSPs")]
            ATT_PKI_DEFAULT_CSPS = 591158,

            [Description("pKIDefaultKeySpec")]
            ATT_PKI_DEFAULT_KEY_SPEC = 591151,

            [Description("pKIEnrollmentAccess")]
            ATT_PKI_ENROLLMENT_ACCESS = 591159,

            [Description("pKIExpirationPeriod")]
            ATT_PKI_EXPIRATION_PERIOD = 591155,

            [Description("pKIExtendedKeyUsage")]
            ATT_PKI_EXTENDED_KEY_USAGE = 591157,

            [Description("pKIKeyUsage")]
            ATT_PKI_KEY_USAGE = 591152,

            [Description("pKIMaxIssuingDepth")]
            ATT_PKI_MAX_ISSUING_DEPTH = 591153,

            [Description("pKIOverlapPeriod")]
            ATT_PKI_OVERLAP_PERIOD = 591156,

            [Description("pKTGuid")]
            ATT_PKT_GUID = 590029,

            [Description("policyReplicationFlags")]
            ATT_POLICY_REPLICATION_FLAGS = 590457,

            [Description("portName")]
            ATT_PORT_NAME = 590052,

            [Description("postalAddress")]
            ATT_POSTAL_ADDRESS = 16,

            [Description("preferredDeliveryMethod")]
            ATT_PREFERRED_DELIVERY_METHOD = 28,

            [Description("preferredOU")]
            ATT_PREFERRED_OU = 589921,

            [Description("presentationAddress")]
            ATT_PRESENTATION_ADDRESS = 29,

            [Description("previousCACertificates")]
            ATT_PREVIOUS_CA_CERTIFICATES = 590516,

            [Description("previousParentCA")]
            ATT_PREVIOUS_PARENT_CA = 590518,

            [Description("printAttributes")]
            ATT_PRINT_ATTRIBUTES = 590071,

            [Description("printBinNames")]
            ATT_PRINT_BIN_NAMES = 590061,

            [Description("printCollate")]
            ATT_PRINT_COLLATE = 590066,

            [Description("printColor")]
            ATT_PRINT_COLOR = 590067,

            [Description("printDuplexSupported")]
            ATT_PRINT_DUPLEX_SUPPORTED = 591135,

            [Description("printEndTime")]
            ATT_PRINT_END_TIME = 590058,

            [Description("printFormName")]
            ATT_PRINT_FORM_NAME = 590059,

            [Description("printKeepPrintedJobs")]
            ATT_PRINT_KEEP_PRINTED_JOBS = 590099,

            [Description("printLanguage")]
            ATT_PRINT_LANGUAGE = 590070,

            [Description("printMACAddress")]
            ATT_PRINT_MAC_ADDRESS = 590112,

            [Description("printMaxCopies")]
            ATT_PRINT_MAX_COPIES = 590065,

            [Description("printMaxResolutionSupported")]
            ATT_PRINT_MAX_RESOLUTION_SUPPORTED = 590062,

            [Description("printMaxXExtent")]
            ATT_PRINT_MAX_X_EXTENT = 590101,

            [Description("printMaxYExtent")]
            ATT_PRINT_MAX_Y_EXTENT = 590102,

            [Description("printMediaReady")]
            ATT_PRINT_MEDIA_READY = 590113,

            [Description("printMediaSupported")]
            ATT_PRINT_MEDIA_SUPPORTED = 590123,

            [Description("printMinXExtent")]
            ATT_PRINT_MIN_X_EXTENT = 590103,

            [Description("printMinYExtent")]
            ATT_PRINT_MIN_Y_EXTENT = 590104,

            [Description("printNetworkAddress")]
            ATT_PRINT_NETWORK_ADDRESS = 590111,

            [Description("printNotify")]
            ATT_PRINT_NOTIFY = 590096,

            [Description("printNumberUp")]
            ATT_PRINT_NUMBER_UP = 590114,

            [Description("printOrientationsSupported")]
            ATT_PRINT_ORIENTATIONS_SUPPORTED = 590064,

            [Description("printOwner")]
            ATT_PRINT_OWNER = 590095,

            [Description("printPagesPerMinute")]
            ATT_PRINT_PAGES_PER_MINUTE = 590455,

            [Description("printSeparatorFile")]
            ATT_PRINT_SEPARATOR_FILE = 590054,

            [Description("printShareName")]
            ATT_PRINT_SHARE_NAME = 590094,

            [Description("printSpooling")]
            ATT_PRINT_SPOOLING = 590098,

            [Description("printStaplingSupported")]
            ATT_PRINT_STAPLING_SUPPORTED = 590105,

            [Description("printStartTime")]
            ATT_PRINT_START_TIME = 590057,

            [Description("printStatus")]
            ATT_PRINT_STATUS = 590097,

            [Description("printerName")]
            ATT_PRINTER_NAME = 590124,

            [Description("priority")]
            ATT_PRIORITY = 590055,

            [Description("privilegeAttributes")]
            ATT_PRIVILEGE_ATTRIBUTES = 590460,

            [Description("privilegeDisplayName")]
            ATT_PRIVILEGE_DISPLAY_NAME = 590458,

            [Description("privilegeHolder")]
            ATT_PRIVILEGE_HOLDER = 590461,

            [Description("privilegeValue")]
            ATT_PRIVILEGE_VALUE = 590459,

            [Description("productCode")]
            ATT_PRODUCT_CODE = 590642,

            [Description("proxyGenerationEnabled")]
            ATT_PROXY_GENERATION_ENABLED = 131595,

            [Description("publicKeyPolicy")]
            ATT_PUBLIC_KEY_POLICY = 590244,

            [Description("qualityOfService")]
            ATT_QUALITY_OF_SERVICE = 590282,

            [Description("queryFilter")]
            ATT_QUERY_FILTER = 591179,

            [Description("queryPolicyBL")]
            ATT_QUERY_POLICY_BL = 590432,

            [Description("queryPoint")]
            ATT_QUERYPOINT = 590504,

            [Description("registeredAddress")]
            ATT_REGISTERED_ADDRESS = 26,

            [Description("remoteServerName")]
            ATT_REMOTE_SERVER_NAME = 589929,

            [Description("remoteSource")]
            ATT_REMOTE_SOURCE = 589931,

            [Description("remoteSourceType")]
            ATT_REMOTE_SOURCE_TYPE = 589932,

            [Description("remoteStorageGUID")]
            ATT_REMOTE_STORAGE_GUID = 590633,

            [Description("replicaSource")]
            ATT_REPLICA_SOURCE = 589933,

            [Description("directReports")]
            ATT_REPORTS = 131508,

            [Description("requiredCategories")]
            ATT_REQUIRED_CATEGORIES = 590145,

            [Description("roleOccupant")]
            ATT_ROLE_OCCUPANT = 33,

            [Description("rpcNsAnnotation")]
            ATT_RPC_NS_ANNOTATION = 590190,

            [Description("rpcNsBindings")]
            ATT_RPC_NS_BINDINGS = 589937,

            [Description("rpcNsCodeset")]
            ATT_RPC_NS_CODESET = 590191,

            [Description("rpcNsEntryFlags")]
            ATT_RPC_NS_ENTRY_FLAGS = 590578,

            [Description("rpcNsGroup")]
            ATT_RPC_NS_GROUP = 589938,

            [Description("rpcNsInterfaceID")]
            ATT_RPC_NS_INTERFACE_ID = 589939,

            [Description("rpcNsObjectID")]
            ATT_RPC_NS_OBJECT_ID = 590136,

            [Description("rpcNsPriority")]
            ATT_RPC_NS_PRIORITY = 589941,

            [Description("rpcNsProfileEntry")]
            ATT_RPC_NS_PROFILE_ENTRY = 589942,

            [Description("rpcNsTransferSyntax")]
            ATT_RPC_NS_TRANSFER_SYNTAX = 590138,

            [Description("schemaUpdate")]
            ATT_SCHEMA_UPDATE = 590305,

            [Description("schemaVersion")]
            ATT_SCHEMA_VERSION = 131543,

            [Description("scopeFlags")]
            ATT_SCOPE_FLAGS = 591178,

            [Description("searchGuide")]
            ATT_SEARCH_GUIDE = 14,

            [Description("seeAlso")]
            ATT_SEE_ALSO = 34,

            [Description("seqNotification")]
            ATT_SEQ_NOTIFICATION = 590328,

            [Description("serialNumber")]
            ATT_SERIAL_NUMBER = 5,

            [Description("serviceBindingInformation")]
            ATT_SERVICE_BINDING_INFORMATION = 590334,

            [Description("serviceClassID")]
            ATT_SERVICE_CLASS_ID = 589946,

            [Description("serviceClassInfo")]
            ATT_SERVICE_CLASS_INFO = 589947,

            [Description("serviceClassName")]
            ATT_SERVICE_CLASS_NAME = 590333,

            [Description("serviceDNSName")]
            ATT_SERVICE_DNS_NAME = 590481,

            [Description("serviceDNSNameType")]
            ATT_SERVICE_DNS_NAME_TYPE = 590483,

            [Description("serviceInstanceVersion")]
            ATT_SERVICE_INSTANCE_VERSION = 590023,

            [Description("setupCommand")]
            ATT_SETUP_COMMAND = 590149,

            [Description("shellContextMenu")]
            ATT_SHELL_CONTEXT_MENU = 590439,

            [Description("shellPropertyPages")]
            ATT_SHELL_PROPERTY_PAGES = 590387,

            [Description("shortServerName")]
            ATT_SHORT_SERVER_NAME = 591033,

            [Description("signatureAlgorithms")]
            ATT_SIGNATURE_ALGORITHMS = 590648,

            [Description("siteGUID")]
            ATT_SITE_GUID = 590186,

            [Description("siteObjectBL")]
            ATT_SITE_OBJECT_BL = 590337,

            [Description("siteServer")]
            ATT_SITE_SERVER = 590318,

            [Description("superScopeDescription")]
            ATT_SUPER_SCOPE_DESCRIPTION = 590535,

            [Description("superScopes")]
            ATT_SUPER_SCOPES = 590534,

            [Description("supportedApplicationContext")]
            ATT_SUPPORTED_APPLICATION_CONTEXT = 30,

            [Description("syncAttributes")]
            ATT_SYNC_ATTRIBUTES = 590490,

            [Description("syncMembership")]
            ATT_SYNC_MEMBERSHIP = 590489,

            [Description("syncWithObject")]
            ATT_SYNC_WITH_OBJECT = 590488,

            [Description("syncWithSID")]
            ATT_SYNC_WITH_SID = 590491,

            [Description("telephoneNumber")]
            ATT_TELEPHONE_NUMBER = 20,

            [Description("teletexTerminalIdentifier")]
            ATT_TELETEX_TERMINAL_IDENTIFIER = 22,

            [Description("telexNumber")]
            ATT_TELEX_NUMBER = 21,

            [Description("primaryTelexNumber")]
            ATT_TELEX_PRIMARY = 590472,

            [Description("timeRefresh")]
            ATT_TIME_REFRESH = 590327,

            [Description("timeVolChange")]
            ATT_TIME_VOL_CHANGE = 590326,

            [Description("treatAsLeaf")]
            ATT_TREAT_AS_LEAF = 590630,

            [Description("treeName")]
            ATT_TREE_NAME = 590484,

            [Description("uNCName")]
            ATT_UNC_NAME = 589961,

            [Description("upgradeProductCode")]
            ATT_UPGRADE_PRODUCT_CODE = 590637,

            [Description("userCert")]
            ATT_USER_CERT = 590469,

            [Description("userSharedFolder")]
            ATT_USER_SHARED_FOLDER = 590575,

            [Description("userSharedFolderOther")]
            ATT_USER_SHARED_FOLDER_OTHER = 590576,

            [Description("USNIntersite")]
            ATT_USN_INTERSITE = 131541,

            [Description("uSNSource")]
            ATT_USN_SOURCE = 590720,

            [Description("vendor")]
            ATT_VENDOR = 590079,

            [Description("versionNumberHi")]
            ATT_VERSION_NUMBER_HI = 590152,

            [Description("versionNumberLo")]
            ATT_VERSION_NUMBER_LO = 590153,

            [Description("volTableGUID")]
            ATT_VOL_TABLE_GUID = 590160,

            [Description("volTableIdxGUID")]
            ATT_VOL_TABLE_IDX_GUID = 590158,

            [Description("volumeCount")]
            ATT_VOLUME_COUNT = 590331,

            [Description("wbemPath")]
            ATT_WBEM_PATH = 590125,

            [Description("winsockAddresses")]
            ATT_WINSOCK_ADDRESSES = 589966,

            [Description("x121Address")]
            ATT_X121_ADDRESS = 24,

            [Description("msFPCAccess")]
            ATT_MSFPC_ACCESS = 1210253381,

            [Description("msFPCActionText")]
            ATT_MSFPC_ACTIONTEXT = 1210253404,

            [Description("msFPCActiveCaching")]
            ATT_MSFPC_ACTIVECACHING = 1210253366,

            [Description("msFPCAdditionalKey")]
            ATT_MSFPC_ADDITIONALKEY = 1210253454,

            [Description("msFPCAdditionalKeys")]
            ATT_MSFPC_ADDITIONALKEYS = 1210253457,

            [Description("msFPCAgeFactor")]
            ATT_MSFPC_AGEFACTOR = 1210253367,

            [Description("msFPCAlertIfActivated")]
            ATT_MSFPC_ALERTIFACTIVATED = 1210253761,

            [Description("msFPCAllInterfaces")]
            ATT_MSFPC_ALLINTERFACES = 1210253645,

            [Description("msFPCAllowLocalPolicy")]
            ATT_MSFPC_ALLOWLOCALPOLICY = 1210253673,

            [Description("msFPCAllowPublishing")]
            ATT_MSFPC_ALLOWPUBLISHING = 1210253728,

            [Description("msFPCAlwaysAuthenticate")]
            ATT_MSFPC_ALWAYSAUTHENTICATE = 1210253641,

            [Description("msFPCAppliesAlways")]
            ATT_MSFPC_APPLIESALWAYS = 1210253646,

            [Description("msFPCAppliesToContentMethod")]
            ATT_MSFPC_APPLIESTOCONTENTMETHOD = 1210253446,

            [Description("msFPCAppliesToDestination")]
            ATT_MSFPC_APPLIESTODESTINATION = 1210253419,

            [Description("msFPCAppliesToMethod")]
            ATT_MSFPC_APPLIESTOMETHOD = 1210253607,

            [Description("msFPCArrayComponents")]
            ATT_MSFPC_ARRAYCOMPONENTS = 1210253788,

            [Description("msFPCArrayDescription")]
            ATT_MSFPC_ARRAYDESCRIPTION = 1210253787,

            [Description("msFPCArrayName")]
            ATT_MSFPC_ARRAYNAME = 1210253671,

            [Description("msFPCArrayParameter1")]
            ATT_MSFPC_ARRAYPARAMETER1 = 1210253790,

            [Description("msFPCArrayVersion")]
            ATT_MSFPC_ARRAYVERSION = 1210253789,

            [Description("msFPCAsymmetricInstallNotificationThreshold")]
            ATT_MSFPC_ASYMMETRICINSTALLNOTIFICATIONTHRESHOLD = 1210253726,

            [Description("msFPCAsymmetricInstallPeriodicCheck")]
            ATT_MSFPC_ASYMMETRICINSTALLPERIODICCHECK = 1210253725,

            [Description("msFPCAuthenticationEnabled")]
            ATT_MSFPC_AUTHENTICATIONENABLED = 1210253542,

            [Description("msFPCAuthenticationInfo")]
            ATT_MSFPC_AUTHENTICATIONINFO = 1210253770,

            [Description("msFPCAutoDetect")]
            ATT_MSFPC_AUTODETECT = 1210253696,

            [Description("msFPCAutoDiscoveryPort")]
            ATT_MSFPC_AUTODISCOVERYPORT = 1210253741,

            [Description("msFPCBackupComment")]
            ATT_MSFPC_BACKUPCOMMENT = 1210253684,

            [Description("msFPCBackupOriginalStorage")]
            ATT_MSFPC_BACKUPORIGINALSTORAGE = 1210253685,

            [Description("msFPCBackupRouteInfo")]
            ATT_MSFPC_BACKUPROUTEINFO = 1210253534,

            [Description("msFPCBackupType")]
            ATT_MSFPC_BACKUPTYPE = 1210253739,

            [Description("msFPCBandwidthClassTemplateUsed")]
            ATT_MSFPC_BANDWIDTHCLASSTEMPLATEUSED = 1210253621,

            [Description("msFPCBandwidthExternalWeight")]
            ATT_MSFPC_BANDWIDTHEXTERNALWEIGHT = 1210253663,

            [Description("msFPCBandwidthInternalWeight")]
            ATT_MSFPC_BANDWIDTHINTERNALWEIGHT = 1210253662,

            [Description("msFPCBasicAuthentication")]
            ATT_MSFPC_BASICAUTHENTICATION = 1210253680,

            [Description("msFPCBlobData")]
            ATT_MSFPC_BLOBDATA = 1210253425,

            [Description("msFPCBrowserConfigAutoDetect")]
            ATT_MSFPC_BROWSERCONFIGAUTODETECT = 1210253745,

            [Description("msFPCBrowserConfigEnabled")]
            ATT_MSFPC_BROWSERCONFIGENABLED = 1210253527,

            [Description("msFPCBrowserConfigScriptAddress")]
            ATT_MSFPC_BROWSERCONFIGSCRIPTADDRESS = 1210253529,

            [Description("msFPCBrowserConfigScriptEnabled")]
            ATT_MSFPC_BROWSERCONFIGSCRIPTENABLED = 1210253746,

            [Description("msFPCBrowserConfigScriptFlag")]
            ATT_MSFPC_BROWSERCONFIGSCRIPTFLAG = 1210253528,

            [Description("msFPCBypassLocalServers")]
            ATT_MSFPC_BYPASSLOCALSERVERS = 1210253536,

            [Description("msFPCCacheByDefault")]
            ATT_MSFPC_CACHEBYDEFAULT = 1210253463,

            [Description("msFPCCacheDirectoryInfo")]
            ATT_MSFPC_CACHEDIRECTORYINFO = 1210253406,

            [Description("msFPCCacheEnableTTL")]
            ATT_MSFPC_CACHEENABLETTL = 1210253462,

            [Description("msFPCCacheNon200Responses")]
            ATT_MSFPC_CACHENON200RESPONSES = 1210253629,

            [Description("msFPCCacheQuestionUrls")]
            ATT_MSFPC_CACHEQUESTIONURLS = 1210253630,

            [Description("msFPCCacheTextOnly")]
            ATT_MSFPC_CACHETEXTONLY = 1210253647,

            [Description("msFPCCacheWithNoLastModDate")]
            ATT_MSFPC_CACHEWITHNOLASTMODDATE = 1210253628,

            [Description("msFPCCARPNameSystem")]
            ATT_MSFPC_CARPNAMESYSTEM = 1210253757,

            [Description("msFPCChainInfo")]
            ATT_MSFPC_CHAININFO = 1210253604,

            [Description("msFPCCleanupFactor")]
            ATT_MSFPC_CLEANUPFACTOR = 1210253458,

            [Description("msFPCCleanupInterval")]
            ATT_MSFPC_CLEANUPINTERVAL = 1210253460,

            [Description("msFPCCleanupTime")]
            ATT_MSFPC_CLEANUPTIME = 1210253459,

            [Description("msFPCCommandLine")]
            ATT_MSFPC_COMMANDLINE = 1210253752,

            [Description("msFPCComponents")]
            ATT_MSFPC_COMPONENTS = 1210253522,

            [Description("msFPCConnectionInfo")]
            ATT_MSFPC_CONNECTIONINFO = 1210253442,

            [Description("msFPCConnectionQuota")]
            ATT_MSFPC_CONNECTIONQUOTA = 1210253688,

            [Description("msFPCConnectionTimeout")]
            ATT_MSFPC_CONNECTIONTIMEOUT = 1210253677,

            [Description("msFPCContentStrings")]
            ATT_MSFPC_CONTENTSTRINGS = 1210253665,

            [Description("msFPCDaysOfWeek")]
            ATT_MSFPC_DAYSOFWEEK = 1210253648,

            [Description("msFPCDescription")]
            ATT_MSFPC_DESCRIPTION = 1210253383,

            [Description("msFPCDestSetData")]
            ATT_MSFPC_DESTSETDATA = 1210253638,

            [Description("msFPCDigestAuthentication")]
            ATT_MSFPC_DIGESTAUTHENTICATION = 1210253686,

            [Description("msFPCDiskCacheFlags")]
            ATT_MSFPC_DISKCACHEFLAGS = 1210253474,

            [Description("msFPCDnsCacheSize")]
            ATT_MSFPC_DNSCACHESIZE = 1210253723,

            [Description("msFPCDnsCacheTtl")]
            ATT_MSFPC_DNSCACHETTL = 1210253724,

            [Description("msFPCDomain")]
            ATT_MSFPC_DOMAIN = 1210253679,

            [Description("msFPCDomainName")]
            ATT_MSFPC_DOMAINNAME = 1210253421,

            [Description("msFPCDynamicPacketFilteringEnabled")]
            ATT_MSFPC_DYNAMICPACKETFILTERINGENABLED = 1210253601,

            [Description("msFPCEnableAllDestinations")]
            ATT_MSFPC_ENABLEALLDESTINATIONS = 1210253395,

            [Description("msFPCEnableAutoDial")]
            ATT_MSFPC_ENABLEAUTODIAL = 1210253714,

            [Description("msFPCEnableAutoDiscovery")]
            ATT_MSFPC_ENABLEAUTODISCOVERY = 1210253699,

            [Description("msFPCEnabled")]
            ATT_MSFPC_ENABLED = 1210253365,

            [Description("msFPCEncryptedData")]
            ATT_MSFPC_ENCRYPTEDDATA = 1210253718,

            [Description("msFPCEnterpriseGUID")]
            ATT_MSFPC_ENTERPRISEGUID = 1210253661,

            [Description("msFPCEventGUID")]
            ATT_MSFPC_EVENTGUID = 1210253453,

            [Description("msFPCFetchUrlFlags")]
            ATT_MSFPC_FETCHURLFLAGS = 1210253649,

            [Description("msFPCFilterDirection")]
            ATT_MSFPC_FILTERDIRECTION = 1210253683,

            [Description("msFPCFilterKind")]
            ATT_MSFPC_FILTERKIND = 1210253669,

            [Description("msFPCFilterType")]
            ATT_MSFPC_FILTERTYPE = 1210253583,

            [Description("msFPCForcePacketFiltering")]
            ATT_MSFPC_FORCEPACKETFILTERING = 1210253729,

            [Description("msFPCFpcEvent")]
            ATT_MSFPC_FPCEVENT = 1210253627,

            [Description("msFPCFQDN")]
            ATT_MSFPC_FQDN = 1210253755,

            [Description("msFPCFreshnessInterval")]
            ATT_MSFPC_FRESHNESSINTERVAL = 1210253464,

            [Description("msFPCFTPCacheEnable")]
            ATT_MSFPC_FTPCACHEENABLE = 1210253377,

            [Description("msFPCFTPTTLUnits")]
            ATT_MSFPC_FTPTTLUNITS = 1210253781,

            [Description("msFPCFTPTTLValue")]
            ATT_MSFPC_FTPTTLVALUE = 1210253378,

            [Description("msFPCGMTTimeZone")]
            ATT_MSFPC_GMTTIMEZONE = 1210253713,

            [Description("msFPCGuid")]
            ATT_MSFPC_GUID = 1210253545,

            [Description("msFPCHidden")]
            ATT_MSFPC_HIDDEN = 1210253747,

            [Description("msFPCHTTPCacheEnable")]
            ATT_MSFPC_HTTPCACHEENABLE = 1210253376,

            [Description("msFPCHttpViaHeaderAlias")]
            ATT_MSFPC_HTTPVIAHEADERALIAS = 1210253494,

            [Description("msFPCICMPInfo")]
            ATT_MSFPC_ICMPINFO = 1210253592,

            [Description("msFPCInitialConnection")]
            ATT_MSFPC_INITIALCONNECTION = 1210253437,

            [Description("msFPCInstallDirectoy")]
            ATT_MSFPC_INSTALLDIRECTOY = 1210253772,

            [Description("msFPCIntegratedWindowsAuthentication")]
            ATT_MSFPC_INTEGRATEDWINDOWSAUTHENTICATION = 1210253687,

            [Description("msFPCInterval")]
            ATT_MSFPC_INTERVAL = 1210253371,

            [Description("msFPCIntExtIPs")]
            ATT_MSFPC_INTEXTIPS = 1210253693,

            [Description("msFPCIntraArrayAddress")]
            ATT_MSFPC_INTRAARRAYADDRESS = 1210253479,

            [Description("msFPCIntrusionDetectionEnabled")]
            ATT_MSFPC_INTRUSIONDETECTIONENABLED = 1210253598,

            [Description("msFPCIP")]
            ATT_MSFPC_IP = 1210253644,

            [Description("msFPCIPFromTo")]
            ATT_MSFPC_IP_FROMTO = 1210253379,

            [Description("msFPCIPFragmentsFilteringEnabled")]
            ATT_MSFPC_IPFRAGMENTSFILTERINGENABLED = 1210253596,

            [Description("msFPCIPHalfScanDetectionEnabled")]
            ATT_MSFPC_IPHALFSCANDETECTIONENABLED = 1210253707,

            [Description("msFPCIPOptionPacketFilteringEnabled")]
            ATT_MSFPC_IPOPTIONPACKETFILTERINGENABLED = 1210253597,

            [Description("msFPCIsDefaultRule")]
            ATT_MSFPC_ISDEFAULTRULE = 1210253507,

            [Description("msFPCLandAttackDetectionEnabled")]
            ATT_MSFPC_LANDATTACKDETECTIONENABLED = 1210253705,

            [Description("msFPCLoadFactor")]
            ATT_MSFPC_LOADFACTOR = 1210253764,

            [Description("msFPCLoadSize")]
            ATT_MSFPC_LOADSIZE = 1210253754,

            [Description("msFPCLocalHost")]
            ATT_MSFPC_LOCALHOST = 1210253590,

            [Description("msFPCLocalPort")]
            ATT_MSFPC_LOCALPORT = 1210253635,

            [Description("msFPCLogInfo")]
            ATT_MSFPC_LOGINFO = 1210253358,

            [Description("msFPCLogMatchingPackets")]
            ATT_MSFPC_LOGMATCHINGPACKETS = 1210253667,

            [Description("msFPCLogPacketsFromAllowedFilters")]
            ATT_MSFPC_LOGPACKETSFROMALLOWEDFILTERS = 1210253779,

            [Description("msFPCMailCc")]
            ATT_MSFPC_MAILCC = 1210253751,

            [Description("msFPCMailFrom")]
            ATT_MSFPC_MAILFROM = 1210253749,

            [Description("msFPCMailServers")]
            ATT_MSFPC_MAILSERVERS = 1210253748,

            [Description("msFPCMailTo")]
            ATT_MSFPC_MAILTO = 1210253750,

            [Description("msFPCMappingQuota")]
            ATT_MSFPC_MAPPINGQUOTA = 1210253689,

            [Description("msFPCMaxDepth")]
            ATT_MSFPC_MAXDEPTH = 1210253650,

            [Description("msFPCMaxPages")]
            ATT_MSFPC_MAXPAGES = 1210253651,

            [Description("msFPCMaxProtectionTime")]
            ATT_MSFPC_MAXPROTECTIONTIME = 1210253631,

            [Description("msFPCMemoryCacheMaxURLSize")]
            ATT_MSFPC_MEMORYCACHEMAXURLSIZE = 1210253778,

            [Description("msFPCMemoryCacheUsagePercent")]
            ATT_MSFPC_MEMORYCACHEUSAGEPERCENT = 1210253777,

            [Description("msFPCMethod")]
            ATT_MSFPC_METHOD = 1210253763,

            [Description("msFPCMinIntervalUnits")]
            ATT_MSFPC_MININTERVALUNITS = 1210253782,

            [Description("msFPCMultiIPs")]
            ATT_MSFPC_MULTIIPS = 1210253773,

            [Description("msFPCMultiServers")]
            ATT_MSFPC_MULTISERVERS = 1210253774,

            [Description("msFPCName")]
            ATT_MSFPC_NAME = 1210253384,

            [Description("msFPCNeverCacheResponse")]
            ATT_MSFPC_NEVERCACHERESPONSE = 1210253402,

            [Description("msFPCNonSecurePublishProtocolRedirection")]
            ATT_MSFPC_NONSECUREPUBLISHPROTOCOLREDIRECTION = 1210253506,

            [Description("msFPCNumberOfConnections")]
            ATT_MSFPC_NUMBEROFCONNECTIONS = 1210253676,

            [Description("msFPCObjectSizeLimit")]
            ATT_MSFPC_OBJECTSIZELIMIT = 1210253368,

            [Description("msFPCObjectSizeUnits")]
            ATT_MSFPC_OBJECTSIZEUNITS = 1210253780,

            [Description("msFPCOperationModesParams")]
            ATT_MSFPC_OPERATIONMODESPARAMS = 1210253455,

            [Description("msFPCOrder")]
            ATT_MSFPC_ORDER = 1210253417,

            [Description("msFPCPacketDirection")]
            ATT_MSFPC_PACKETDIRECTION = 1210253585,

            [Description("msFPCPacketFiltersInfo")]
            ATT_MSFPC_PACKETFILTERSINFO = 1210253708,

            [Description("msFPCParameter1")]
            ATT_MSFPC_PARAMETER1 = 1210253771,

            [Description("msFPCParameters")]
            ATT_MSFPC_PARAMETERS = 1210253456,

            [Description("msFPCPassword")]
            ATT_MSFPC_PASSWORD = 1210253610,

            [Description("msFPCPath")]
            ATT_MSFPC_PATH = 1210253424,

            [Description("msFPCPFServerInfo")]
            ATT_MSFPC_PFSERVERINFO = 1210253582,

            [Description("msFPCPingOfDeathDetectionEnabled")]
            ATT_MSFPC_PINGOFDEATHDETECTIONENABLED = 1210253706,

            [Description("msFPCPolicyName")]
            ATT_MSFPC_POLICYNAME = 1210253672,

            [Description("msFPCPolicySettings")]
            ATT_MSFPC_POLICYSETTINGS = 1210253765,

            [Description("msFPCPollInfo")]
            ATT_MSFPC_POLLINFO = 1210253769,

            [Description("msFPCPriority")]
            ATT_MSFPC_PRIORITY = 1210253731,

            [Description("msFPCProductID")]
            ATT_MSFPC_PRODUCT_ID = 1210253516,

            [Description("msFPCProtocolRuleAction")]
            ATT_MSFPC_PROTOCOLRULEACTION = 1210253613,

            [Description("msFPCProtocolSelectionMethod")]
            ATT_MSFPC_PROTOCOLSELECTIONMETHOD = 1210253612,

            [Description("msFPCPublicKey")]
            ATT_MSFPC_PUBLICKEY = 1210253608,

            [Description("msFPCPubRuleInfo")]
            ATT_MSFPC_PUBRULEINFO = 1210253767,

            [Description("msFPCRasPhoneBookEntry")]
            ATT_MSFPC_RASPHONEBOOKENTRY = 1210253715,

            [Description("msFPCRefInfo")]
            ATT_MSFPC_REFINFO = 1210253722,

            [Description("msFPCRelativePath")]
            ATT_MSFPC_RELATIVEPATH = 1210253503,

            [Description("msFPCResolveInArray")]
            ATT_MSFPC_RESOLVEINARRAY = 1210253738,

            [Description("msFPCRouteDestinations")]
            ATT_MSFPC_ROUTEDESTINATIONS = 1210253431,

            [Description("msFPCRouteInfo")]
            ATT_MSFPC_ROUTEINFO = 1210253768,

            [Description("msFPCRoutingCacheAction")]
            ATT_MSFPC_ROUTINGCACHEACTION = 1210253674,

            [Description("msFPCSchedTimes")]
            ATT_MSFPC_SCHEDTIMES = 1210253652,

            [Description("msFPCScheduleTemplate")]
            ATT_MSFPC_SCHEDULETEMPLATE = 1210253420,

            [Description("msFPCSchemaVersion")]
            ATT_MSFPC_SCHEMAVERSION = 1210253518,

            [Description("msFPCSCRuleInfo")]
            ATT_MSFPC_SCRULEINFO = 1210253766,

            [Description("msFPCSecurePublishProtocolRedirection")]
            ATT_MSFPC_SECUREPUBLISHPROTOCOLREDIRECTION = 1210253736,

            [Description("msFPCSecurityLevel")]
            ATT_MSFPC_SECURITYLEVEL = 1210253664,

            [Description("msFPCServerName")]
            ATT_MSFPC_SERVERNAME = 1210253436,

            [Description("msFPCServerOrArrayName")]
            ATT_MSFPC_SERVERORARRAYNAME = 1210253525,

            [Description("msFPCServerProtectFactor")]
            ATT_MSFPC_SERVERPROTECTFACTOR = 1210253375,

            [Description("msFPCServerProtectionEnable")]
            ATT_MSFPC_SERVERPROTECTIONENABLE = 1210253374,

            [Description("msFPCServiceRestartID")]
            ATT_MSFPC_SERVICERESTARTID = 1210253744,

            [Description("msFPCServices")]
            ATT_MSFPC_SERVICES = 1210253753,

            [Description("msFPCSessionKey")]
            ATT_MSFPC_SESSIONKEY = 1210253609,

            [Description("msFPCSiteName")]
            ATT_MSFPC_SITENAME = 1210253732,

            [Description("msFPCSizeLimitEnable")]
            ATT_MSFPC_SIZELIMITENABLE = 1210253369,

            [Description("msFPCSSLCertificateAuthentication")]
            ATT_MSFPC_SSLCERTIFICATEAUTHENTICATION = 1210253721,

            [Description("msFPCSSLCertificateHash")]
            ATT_MSFPC_SSLCERTIFICATEHASH = 1210253737,

            [Description("msFPCSSLPort")]
            ATT_MSFPC_SSLPORT = 1210253682,

            [Description("msFPCSSLRequireSecureChannel")]
            ATT_MSFPC_SSLREQUIRESECURECHANNEL = 1210253720,

            [Description("msFPCStatus")]
            ATT_MSFPC_STATUS = 1210253775,

            [Description("msFPCStayInDomain")]
            ATT_MSFPC_STAYINDOMAIN = 1210253657,

            [Description("msFPCSystemProtocol")]
            ATT_MSFPC_SYSTEMPROTOCOL = 1210253740,

            [Description("msFPCTaskPeriod")]
            ATT_MSFPC_TASKPERIOD = 1210253658,

            [Description("msFPCTcpBufferSize")]
            ATT_MSFPC_TCPBUFFERSIZE = 1210253690,

            [Description("msFPCTCPPort")]
            ATT_MSFPC_TCPPORT = 1210253681,

            [Description("msFPCTTL")]
            ATT_MSFPC_TTL = 1210253659,

            [Description("msFPCTunnelPorts")]
            ATT_MSFPC_TUNNELPORTS = 1210253742,

            [Description("msFPCUdpBombDetectionEnabled")]
            ATT_MSFPC_UDPBOMBDETECTIONENABLED = 1210253709,

            [Description("msFPCUdpBufferSize")]
            ATT_MSFPC_UDPBUFFERSIZE = 1210253691,

            [Description("msFPCUnlimitedNumberOfConnections")]
            ATT_MSFPC_UNLIMITEDNUMBEROFCONNECTIONS = 1210253675,

            [Description("msFPCUpstreamResolveSystem")]
            ATT_MSFPC_UPSTREAMRESOLVESYSTEM = 1210253758,

            [Description("msFPCURL")]
            ATT_MSFPC_URL = 1210253660,

            [Description("msFPCUsageProfile")]
            ATT_MSFPC_USAGEPROFILE = 1210253776,

            [Description("msFPCUseDefaultPolicy")]
            ATT_MSFPC_USEDEFAULTPOLICY = 1210253730,

            [Description("msFPCUseProxyInfo")]
            ATT_MSFPC_USEPROXYINFO = 1210253716,

            [Description("msFPCUserName")]
            ATT_MSFPC_USERNAME = 1210253541,

            [Description("msFPCVendor")]
            ATT_MSFPC_VENDOR = 1210253524,

            [Description("msFPCVersion")]
            ATT_MSFPC_VERSION = 1210253385,

            [Description("msFPCWindowsQosEnabled")]
            ATT_MSFPC_WINDOWSQOSENABLED = 1210253727,

            [Description("msFPCWinOutOfBandDetectionEnabled")]
            ATT_MSFPC_WINOUTOFBANDDETECTIONENABLED = 1210253704,

            [Description("msFPCWinsockClientInfo")]
            ATT_MSFPC_WINSOCKCLIENTINFO = 1210253526,

            [Description("msExchAccessControlMap")]
            ATT_MS_EXCH_ACCESS_CONTROL_MAP = 1736704064,

            [Description("activationSchedule")]
            ATT_MS_EXCH_ACTIVATION_SCHEDULE = 131285,

            [Description("activationStyle")]
            ATT_MS_EXCH_ACTIVATION_STYLE = 131145,

            [Description("msExchADCOptions")]
            ATT_MS_EXCH_ADC_OPTIONS = 1736704041,

            [Description("msExchAdditionalDNMap")]
            ATT_MS_EXCH_ADDITIONAL_DN_MAP = 1736704042,

            [Description("businessRoles")]
            ATT_MS_EXCH_BUSINESS_ROLES = 131177,

            [Description("msExchCorrelationAttribute")]
            ATT_MS_EXCH_CORRELATION_ATTRIBUTE = 1736704043,

            [Description("msExchDereferenceAliases")]
            ATT_MS_EXCH_DEREFERENCE_ALIASES = 1736704002,

            [Description("msExchDoFullReplication")]
            ATT_MS_EXCH_DO_FULL_REPLICATION = 1736704038,

            [Description("msExchIsBridgeheadSite")]
            ATT_MS_EXCH_IS_BRIDGEHEAD_SITE = 1736704035,

            [Description("msExchNTAccountOptions")]
            ATT_MS_EXCH_NT_ACCOUNT_OPTIONS = 1736704044,

            [Description("msExchNtdsExportContainers")]
            ATT_MS_EXCH_NTDS_EXPORT_CONTAINERS = 1736704033,

            [Description("msExchNtdsImportContainer")]
            ATT_MS_EXCH_NTDS_IMPORT_CONTAINER = 1736704034,

            [Description("msExchRemotePrivateISList")]
            ATT_MS_EXCH_REMOTE_PRIVATE_IS_LIST = 1736704046,

            [Description("msExchRemoteServerList")]
            ATT_MS_EXCH_REMOTE_SERVER_LIST = 1736704045,

            [Description("msExchReplicateNow")]
            ATT_MS_EXCH_REPLICATE_NOW = 1736704053,

            [Description("msExchServer1AlwaysCreateAs")]
            ATT_MS_EXCH_SERVER1_ALWAYS_CREATE_AS = 1736704027,

            [Description("msExchServer1AuthenticationCredentials")]
            ATT_MS_EXCH_SERVER1_AUTHENTICATION_CREDENTIALS = 1736704009,

            [Description("msExchServer1AuthenticationPassword")]
            ATT_MS_EXCH_SERVER1_AUTHENTICATION_PASSWORD = 1736704011,

            [Description("msExchServer1AuthenticationType")]
            ATT_MS_EXCH_SERVER1_AUTHENTICATION_TYPE = 1736704007,

            [Description("msExchServer1DeletionOption")]
            ATT_MS_EXCH_SERVER1_DELETION_OPTION = 1736704021,

            [Description("msExchServer1ExportContainers")]
            ATT_MS_EXCH_SERVER1_EXPORT_CONTAINERS = 1736704013,

            [Description("msExchServer1Flags")]
            ATT_MS_EXCH_SERVER1_FLAGS = 1736704061,

            [Description("msExchServer1HighestUSN")]
            ATT_MS_EXCH_SERVER1_HIGHEST_USN = 1736704029,

            [Description("msExchServer1ImportContainer")]
            ATT_MS_EXCH_SERVER1_IMPORT_CONTAINER = 1736704015,

            [Description("msExchServer1LastUpdateTime")]
            ATT_MS_EXCH_SERVER1_LAST_UPDATE_TIME = 1736704031,

            [Description("msExchServer1NetworkAddress")]
            ATT_MS_EXCH_SERVER1_NETWORK_ADDRESS = 1736704003,

            [Description("msExchServer1NTAccountDomain")]
            ATT_MS_EXCH_SERVER1_NT_ACCOUNT_DOMAIN = 1736704050,

            [Description("msExchServer1ObjectMatch")]
            ATT_MS_EXCH_SERVER1_OBJECT_MATCH = 1736704054,

            [Description("msExchServer1PageSize")]
            ATT_MS_EXCH_SERVER1_PAGE_SIZE = 1736704025,

            [Description("msExchServer1Port")]
            ATT_MS_EXCH_SERVER1_PORT = 1736704005,

            [Description("msExchServer1SchemaMap")]
            ATT_MS_EXCH_SERVER1_SCHEMA_MAP = 1736704017,

            [Description("msExchServer1SearchFilter")]
            ATT_MS_EXCH_SERVER1_SEARCH_FILTER = 1736704019,

            [Description("msExchServer1SSLPort")]
            ATT_MS_EXCH_SERVER1_SSL_PORT = 1736704039,

            [Description("msExchServer1Type")]
            ATT_MS_EXCH_SERVER1_TYPE = 1736704023,

            [Description("msExchServer2AlwaysCreateAs")]
            ATT_MS_EXCH_SERVER2_ALWAYS_CREATE_AS = 1736704028,

            [Description("msExchServer2AuthenticationCredentials")]
            ATT_MS_EXCH_SERVER2_AUTHENTICATION_CREDENTIALS = 1736704010,

            [Description("msExchServer2AuthenticationPassword")]
            ATT_MS_EXCH_SERVER2_AUTHENTICATION_PASSWORD = 1736704012,

            [Description("msExchServer2AuthenticationType")]
            ATT_MS_EXCH_SERVER2_AUTHENTICATION_TYPE = 1736704008,

            [Description("msExchServer2DeletionOption")]
            ATT_MS_EXCH_SERVER2_DELETION_OPTION = 1736704022,

            [Description("msExchServer2ExportContainers")]
            ATT_MS_EXCH_SERVER2_EXPORT_CONTAINERS = 1736704014,

            [Description("msExchServer2Flags")]
            ATT_MS_EXCH_SERVER2_FLAGS = 1736704062,

            [Description("msExchServer2HighestUSN")]
            ATT_MS_EXCH_SERVER2_HIGHEST_USN = 1736704030,

            [Description("msExchServer2ImportContainer")]
            ATT_MS_EXCH_SERVER2_IMPORT_CONTAINER = 1736704016,

            [Description("msExchServer2LastUpdateTime")]
            ATT_MS_EXCH_SERVER2_LAST_UPDATE_TIME = 1736704032,

            [Description("msExchServer2NetworkAddress")]
            ATT_MS_EXCH_SERVER2_NETWORK_ADDRESS = 1736704004,

            [Description("msExchServer2NTAccountDomain")]
            ATT_MS_EXCH_SERVER2_NT_ACCOUNT_DOMAIN = 1736704051,

            [Description("msExchServer2ObjectMatch")]
            ATT_MS_EXCH_SERVER2_OBJECT_MATCH = 1736704055,

            [Description("msExchServer2PageSize")]
            ATT_MS_EXCH_SERVER2_PAGE_SIZE = 1736704026,

            [Description("msExchServer2Port")]
            ATT_MS_EXCH_SERVER2_PORT = 1736704006,

            [Description("msExchServer2SchemaMap")]
            ATT_MS_EXCH_SERVER2_SCHEMA_MAP = 1736704018,

            [Description("msExchServer2SearchFilter")]
            ATT_MS_EXCH_SERVER2_SEARCH_FILTER = 1736704020,

            [Description("msExchServer2SSLPort")]
            ATT_MS_EXCH_SERVER2_SSL_PORT = 1736704040,

            [Description("msExchServer2Type")]
            ATT_MS_EXCH_SERVER2_TYPE = 1736704024,

            [Description("msExchSynchronizationDirection")]
            ATT_MS_EXCH_SYNCHRONIZATION_DIRECTION = 1736704001,

            [Description("personalPager")]
            ATT_MS_EXCH_TELEPHONE_PERSONAL_PAGER = 131684,

            [Description("msExchHomeSyncService")]
            ATT_MS_EXCH_HOME_SYNC_SERVICE = 1736704036,

            [Description("msExchChildSyncAgreements")]
            ATT_MS_EXCH_CHILD_SYNC_AGREEMENTS = 1736704037,

            [Description("msExchCASchemaPolicy")]
            ATT_MS_EXCH_CA_SCHEMA_POLICY = 1736704056,

            [Description("msExchSchemaPolicyConsumers")]
            ATT_MS_EXCH_SCHEMA_POLICY_CONSUMERS = 1736704057,

            [Description("msExchServer1IsBridgehead")]
            ATT_MS_EXCH_SERVER1_IS_BRIDGEHEAD = 1736704077,

            [Description("msExchServer2IsBridgehead")]
            ATT_MS_EXCH_SERVER2_IS_BRIDGEHEAD = 1736704078,

            [Description("msExchADCObjectType")]
            ATT_MS_EXCH_ADC_OBJECT_TYPE = 1736704084,

            [Description("msExchExchangeSite")]
            ATT_MS_EXCH_EXCHANGE_SITE = 1736704085,

            [Description("msExchServer1HighestUSNVector")]
            ATT_MS_EXCH_SERVER1_HIGHEST_USN_VECTOR = 1736704086,

            [Description("msExchServer2HighestUSNVector")]
            ATT_MS_EXCH_SERVER2_HIGHEST_USN_VECTOR = 1736704087,

            [Description("promoExpiration")]
            ATT_MS_EXCH_PROMO_EXPIRATION = 131612,

            [Description("sSelector")]
            ATT_MS_EXCH_S_SELECTOR = 131356,

            [Description("sSelectorInbound")]
            ATT_MS_EXCH_S_SELECTOR_INBOUND = 131118,

            [Description("type")]
            ATT_MS_EXCH_TYPE = 131645,

            [Description("homeMDBBL")]
            ATT_MS_EXCH_HOME_MDB_BL = 131465,

            [Description("info")]
            ATT_COMMENT = 131153,

            [Description("msExchMemberBaseDN")]
            ATT_MS_EXCH_MEMBER_BASE_DN = 1736716524,

            [Description("msExchMemberFilter")]
            ATT_MS_EXCH_MEMBER_FILTER = 1736716522,

            [Description("networkAddress")]
            ATT_NETWORK_ADDRESS = 131531,

            [Description("owner")]
            ATT_OWNER = 32,

            [Description("physicalDeliveryOfficeName")]
            ATT_PHYSICAL_DELIVERY_OFFICE_NAME = 19,

            [Description("msExchAddGroupsToToken")]
            ATT_MS_EXCH_ADD_GROUPS_TO_TOKEN = 1736704095,

            [Description("msExchHostPortalServices")]
            ATT_MS_EXCH_HOST_PORTAL_SERVICES = 1030521746,

            [Description("facsimileTelephoneNumber")]
            ATT_FACSIMILE_TELEPHONE_NUMBER = 23,

            [Description("initials")]
            ATT_INITIALS = 43,

            [Description("otherFacsimileTelephoneNumber")]
            ATT_PHONE_FAX_OTHER = 590470,

            [Description("otherHomePhone")]
            ATT_PHONE_HOME_OTHER = 131349,

            [Description("otherMobile")]
            ATT_PHONE_MOBILE_OTHER = 590471,

            [Description("mobile")]
            ATT_PHONE_MOBILE_PRIMARY = 1376297,

            [Description("otherTelephone")]
            ATT_PHONE_OFFICE_OTHER = 131090,

            [Description("otherPager")]
            ATT_PHONE_PAGER_OTHER = 131190,

            [Description("pager")]
            ATT_PHONE_PAGER_PRIMARY = 1376298,

            [Description("postOfficeBox")]
            ATT_POST_OFFICE_BOX = 18,

            [Description("postalCode")]
            ATT_POSTAL_CODE = 17,

            [Description("wWWHomePage")]
            ATT_WWW_HOME_PAGE = 131536,

            [Description("url")]
            ATT_WWW_PAGE_OTHER = 590573,

            [Description("msExchMoveToLSA")]
            ATT_MS_EXCH_MOVE_TO_LSA = 1736704088,

            [Description("msExchInterOrgAddressType")]
            ATT_MS_EXCH_INTER_ORG_ADDRESS_TYPE = 1736704094,

            [Description("msExchPFDefaultAdminACL")]
            ATT_MS_EXCH_PF_DEFAULT_ADMIN_ACL = 1030521715,

            [Description("msExchPFDSContainer")]
            ATT_MS_EXCH_PF_DS_CONTAINER = 1736715034,

            [Description("msExchAccessFlags")]
            ATT_MS_EXCH_ACCESS_FLAGS = 1736706016,

            [Description("msExchAccessSSLFlags")]
            ATT_MS_EXCH_ACCESS_SSL_FLAGS = 1736706006,

            [Description("aDMD")]
            ATT_MS_EXCH_ADMD = 131304,

            [Description("msExchAdminACL")]
            ATT_MS_EXCH_ADMIN_ACL = 1736706011,

            [Description("adminExtensionDLL")]
            ATT_MS_EXCH_ADMIN_EXTENSION_DLL = 131167,

            [Description("msExchAdminGroupMode")]
            ATT_MS_EXCH_ADMIN_GROUP_MODE = 1030521694,

            [Description("msExchAdminMailbox")]
            ATT_MS_EXCH_ADMIN_MAILBOX = 1736705034,

            [Description("msExchAliasGenFormat")]
            ATT_MS_EXCH_ALIAS_GEN_FORMAT = 1030521690,

            [Description("msExchAliasGenType")]
            ATT_MS_EXCH_ALIAS_GEN_TYPE = 1030521691,

            [Description("msExchAliasGenUniqueness")]
            ATT_MS_EXCH_ALIAS_GEN_UNIQUENESS = 1030521692,

            [Description("msExchAllowAdditionalResources")]
            ATT_MS_EXCH_ALLOW_ADDITIONAL_RESOURCES = 1736713006,

            [Description("msExchAllowTimeExtensions")]
            ATT_MS_EXCH_ALLOW_TIME_EXTENSIONS = 1736713005,

            [Description("anonymousAccess")]
            ATT_MS_EXCH_ANONYMOUS_ACCESS = 131554,

            [Description("anonymousAccount")]
            ATT_MS_EXCH_ANONYMOUS_ACCOUNT = 131633,

            [Description("associationLifetime")]
            ATT_MS_EXCH_ASSOCIATION_LIFETIME = 131221,

            [Description("msExchAuditFlags")]
            ATT_MS_EXCH_AUDIT_FLAGS = 1736713004,

            [Description("msExchAuthenticationFlags")]
            ATT_MS_EXCH_AUTHENTICATION_FLAGS = 1736706003,

            [Description("authorizedDomain")]
            ATT_MS_EXCH_AUTHORIZED_DOMAIN = 131274,

            [Description("authorizedPassword")]
            ATT_MS_EXCH_AUTHORIZED_PASSWORD = 131265,

            [Description("authorizedUser")]
            ATT_MS_EXCH_AUTHORIZED_USER = 131348,

            [Description("availableAuthorizationPackages")]
            ATT_MS_EXCH_AVAILABLE_AUTHORIZATION_PACKAGES = 131548,

            [Description("availableDistributions")]
            ATT_MS_EXCH_AVAILABLE_DISTRIBUTIONS = 131558,

            [Description("msExchAvailableServers")]
            ATT_MS_EXCH_AVAILABLE_SERVERS = 1736713020,

            [Description("msExchBackgroundThreads")]
            ATT_MS_EXCH_BACKGROUND_THREADS = 1736715038,

            [Description("msExchBasicAuthenticationDomain")]
            ATT_MS_EXCH_BASIC_AUTHENTICATION_DOMAIN = 1736706010,

            [Description("bridgeheadServers")]
            ATT_MS_EXCH_BRIDGEHEAD_SERVERS = 131535,

            [Description("canPreserveDNs")]
            ATT_MS_EXCH_CAN_PRESERVE_DNS = 131527,

            [Description("msExchCatalog")]
            ATT_MS_EXCH_CATALOG = 1736715052,

            [Description("msExchccMailADEProp")]
            ATT_MS_EXCH_CCMAIL_ADE_PROP = 1736705036,

            [Description("msExchccMailFilterType")]
            ATT_MS_EXCH_CCMAIL_FILTER_TYPE = 1736705038,

            [Description("msExchccMailImportExportVersion")]
            ATT_MS_EXCH_CCMAIL_IMPORT_EXPORT_VERSION = 1736705035,

            [Description("msExchccMailKeepForwardHistory")]
            ATT_MS_EXCH_CCMAIL_KEEP_FORWARD_HISTORY = 1736705037,

            [Description("msExchccMailPOName")]
            ATT_MS_EXCH_CCMAIL_PO_NAME = 1736705031,

            [Description("msExchccMailPOPath")]
            ATT_MS_EXCH_CCMAIL_PO_PATH = 1736705033,

            [Description("msExchCertificate")]
            ATT_MS_EXCH_CERTIFICATE = 1736713012,

            [Description("certificateChainV3")]
            ATT_MS_EXCH_CERTIFICATE_CHAIN_V3 = 131634,

            [Description("certificateRevocationListV1")]
            ATT_MS_EXCH_CERTIFICATE_REVOCATION_LIST_V1 = 131636,

            [Description("certificateRevocationListV3")]
            ATT_MS_EXCH_CERTIFICATE_REVOCATION_LIST_V3 = 131635,

            [Description("characterSet")]
            ATT_MS_EXCH_CHARACTER_SET = 131552,

            [Description("characterSetList")]
            ATT_MS_EXCH_CHARACTER_SET_LIST = 131549,

            [Description("msExchChatAccess")]
            ATT_MS_EXCH_CHAT_ACCESS = 1736712044,

            [Description("msExchChatAdminMessage")]
            ATT_MS_EXCH_CHAT_ADMIN_MESSAGE = 1736712003,

            [Description("msExchChatBanMask")]
            ATT_MS_EXCH_CHAT_BAN_MASK = 1736712040,

            [Description("msExchChatBanReason")]
            ATT_MS_EXCH_CHAT_BAN_REASON = 1736712043,

            [Description("msExchChatBroadcastAddress")]
            ATT_MS_EXCH_CHAT_BROADCAST_ADDRESS = 1736712009,

            [Description("msExchChatChannelAutoCreate")]
            ATT_MS_EXCH_CHAT_CHANNEL_AUTO_CREATE = 1736712020,

            [Description("msExchChatChannelFlags")]
            ATT_MS_EXCH_CHAT_CHANNEL_FLAGS = 1736712026,

            [Description("msExchChatChannelHostKey")]
            ATT_MS_EXCH_CHAT_CHANNEL_HOST_KEY = 1736712023,

            [Description("msExchChatChannelJoinMessage")]
            ATT_MS_EXCH_CHAT_CHANNEL_JOIN_MESSAGE = 1736712030,

            [Description("msExchChatChannelKey")]
            ATT_MS_EXCH_CHAT_CHANNEL_KEY = 1736712021,

            [Description("msExchChatChannelLanguage")]
            ATT_MS_EXCH_CHAT_CHANNEL_LANGUAGE = 1736712028,

            [Description("msExchChatChannelLCID")]
            ATT_MS_EXCH_CHAT_CHANNEL_LCID = 1736712029,

            [Description("msExchChatChannelLimit")]
            ATT_MS_EXCH_CHAT_CHANNEL_LIMIT = 1736712010,

            [Description("msExchChatChannelMode")]
            ATT_MS_EXCH_CHAT_CHANNEL_MODE = 1736712006,

            [Description("msExchChatChannelName")]
            ATT_MS_EXCH_CHAT_CHANNEL_NAME = 1736712019,

            [Description("msExchChatChannelOwnerKey")]
            ATT_MS_EXCH_CHAT_CHANNEL_OWNER_KEY = 1736712022,

            [Description("msExchChatChannelPartMessage")]
            ATT_MS_EXCH_CHAT_CHANNEL_PART_MESSAGE = 1736712031,

            [Description("msExchChatChannelPICS")]
            ATT_MS_EXCH_CHAT_CHANNEL_PICS = 1736712027,

            [Description("msExchChatChannelSubject")]
            ATT_MS_EXCH_CHAT_CHANNEL_SUBJECT = 1736712025,

            [Description("msExchChatChannelTopic")]
            ATT_MS_EXCH_CHAT_CHANNEL_TOPIC = 1736712024,

            [Description("msExchChatClassIdentMask")]
            ATT_MS_EXCH_CHAT_CLASS_IDENT_MASK = 1736712032,

            [Description("msExchChatClassIP")]
            ATT_MS_EXCH_CHAT_CLASS_IP = 1736712033,

            [Description("msExchChatClientPort")]
            ATT_MS_EXCH_CHAT_CLIENT_PORT = 1736712007,

            [Description("msExchChatDNSReverseMode")]
            ATT_MS_EXCH_CHAT_DNS_REVERSE_MODE = 1736712013,

            [Description("msExchChatDuration")]
            ATT_MS_EXCH_CHAT_DURATION = 1736712042,

            [Description("msExchChatEnableAnonymous")]
            ATT_MS_EXCH_CHAT_ENABLE_ANONYMOUS = 1736712011,

            [Description("msExchChatEnableAuthenticated")]
            ATT_MS_EXCH_CHAT_ENABLE_AUTHENTICATED = 1736712012,

            [Description("msExchChatInputFloodLimit")]
            ATT_MS_EXCH_CHAT_INPUT_FLOOD_LIMIT = 1736712038,

            [Description("msExchChatMaxAnonymous")]
            ATT_MS_EXCH_CHAT_MAX_ANONYMOUS = 1736712015,

            [Description("msExchChatMaxConnections")]
            ATT_MS_EXCH_CHAT_MAX_CONNECTIONS = 1736712014,

            [Description("msExchChatMaxMemberships")]
            ATT_MS_EXCH_CHAT_MAX_MEMBERSHIPS = 1736712016,

            [Description("msExchChatMessageLag")]
            ATT_MS_EXCH_CHAT_MESSAGE_LAG = 1736712034,

            [Description("msExchChatMOTD")]
            ATT_MS_EXCH_CHAT_MOTD = 1736712004,

            [Description("msExchChatNetworkMode")]
            ATT_MS_EXCH_CHAT_NETWORK_MODE = 1736712045,

            [Description("msExchChatNetworkName")]
            ATT_MS_EXCH_CHAT_NETWORK_NAME = 1736712001,

            [Description("msExchChatNickDelay")]
            ATT_MS_EXCH_CHAT_NICK_DELAY = 1736712036,

            [Description("msExchChatOutputSaturation")]
            ATT_MS_EXCH_CHAT_OUTPUT_SATURATION = 1736712039,

            [Description("msExchChatPingDelay")]
            ATT_MS_EXCH_CHAT_PING_DELAY = 1736712037,

            [Description("msExchChatProtectionLevel")]
            ATT_MS_EXCH_CHAT_PROTECTION_LEVEL = 1736712035,

            [Description("msExchChatServerPort")]
            ATT_MS_EXCH_CHAT_SERVER_PORT = 1736712008,

            [Description("msExchChatStartTime")]
            ATT_MS_EXCH_CHAT_START_TIME = 1736712041,

            [Description("msExchChatTitle")]
            ATT_MS_EXCH_CHAT_TITLE = 1736712002,

            [Description("clientAccessEnabled")]
            ATT_MS_EXCH_CLIENT_ACCESS_ENABLED = 131631,

            [Description("clockAlertOffset")]
            ATT_MS_EXCH_CLOCK_ALERT_OFFSET = 131237,

            [Description("clockAlertRepair")]
            ATT_MS_EXCH_CLOCK_ALERT_REPAIR = 131236,

            [Description("clockWarningOffset")]
            ATT_MS_EXCH_CLOCK_WARNING_OFFSET = 131249,

            [Description("clockWarningRepair")]
            ATT_MS_EXCH_CLOCK_WARNING_REPAIR = 131238,

            [Description("compromisedKeyList")]
            ATT_MS_EXCH_COMPROMISED_KEY_LIST = 131614,

            [Description("computerName")]
            ATT_MS_EXCH_COMPUTER_NAME = 131092,

            [Description("connectedDomains")]
            ATT_MS_EXCH_CONNECTED_DOMAINS = 131283,

            [Description("connectionListFilter")]
            ATT_MS_EXCH_CONNECTION_LIST_FILTER = 131547,

            [Description("connectionListFilterType")]
            ATT_MS_EXCH_CONNECTION_LIST_FILTER_TYPE = 131598,

            [Description("msExchConnectorType")]
            ATT_MS_EXCH_CONNECTOR_TYPE = 1736716508,

            [Description("containerInfo")]
            ATT_MS_EXCH_CONTAINER_INFO = 131368,

            [Description("controlMsgFolderID")]
            ATT_MS_EXCH_CONTROL_MSG_FOLDER_ID = 131555,

            [Description("controlMsgRules")]
            ATT_MS_EXCH_CONTROL_MSG_RULES = 131557,

            [Description("msExchConvertToFixedFont")]
            ATT_MS_EXCH_CONVERT_TO_FIXED_FONT = 1736715021,

            [Description("crossCertificateCRL")]
            ATT_MS_EXCH_CROSS_CERTIFICATE_CRL = 131637,

            [Description("msExchCTPClassGUID")]
            ATT_MS_EXCH_CTP_CLASS_GUID = 1736713008,

            [Description("msExchCTPFrameHint")]
            ATT_MS_EXCH_CTP_FRAME_HINT = 1736713010,

            [Description("msExchCTPPropertySchema")]
            ATT_MS_EXCH_CTP_PROPERTY_SCHEMA = 1736713022,

            [Description("msExchCTPProviderGUID")]
            ATT_MS_EXCH_CTP_PROVIDER_GUID = 1736713007,

            [Description("msExchCTPProviderName")]
            ATT_MS_EXCH_CTP_PROVIDER_NAME = 1736713021,

            [Description("msExchCTPRequireCMSAuthentication")]
            ATT_MS_EXCH_CTP_REQUIRE_CMS_AUTHENTICATION = 1736713023,

            [Description("msExchCTPSnapinGUID")]
            ATT_MS_EXCH_CTP_SNAPIN_GUID = 1736713009,

            [Description("msExchDatabaseSessionAddend")]
            ATT_MS_EXCH_DATABASE_SESSION_ADDEND = 1736715039,

            [Description("msExchDatabaseSessionIncrement")]
            ATT_MS_EXCH_DATABASE_SESSION_INCREMENT = 1736715040,

            [Description("msExchDefaultAdminGroup")]
            ATT_MS_EXCH_DEFAULT_ADMIN_GROUP = 1030521695,

            [Description("msExchDefaultDomain")]
            ATT_MS_EXCH_DEFAULT_DOMAIN = 1736706012,

            [Description("msExchDefaultLogonDomain")]
            ATT_MS_EXCH_DEFAULT_LOGON_DOMAIN = 1736719001,

            [Description("defaultMessageFormat")]
            ATT_MS_EXCH_DEFAULT_MESSAGE_FORMAT = 131644,

            [Description("delegateUser")]
            ATT_MS_EXCH_DELEGATE_USER = 131663,

            [Description("delivEITs")]
            ATT_MS_EXCH_DELIV_EITS = 131211,

            [Description("msExchDeliveryOrder")]
            ATT_MS_EXCH_DELIVERY_ORDER = 1736705003,

            [Description("msExchDestBHAddress")]
            ATT_MS_EXCH_DEST_BH_ADDRESS = 1736716510,

            [Description("msExchDestinationRGDN")]
            ATT_MS_EXCH_DESTINATION_RG_DN = 1736716507,

            [Description("diagnosticRegKey")]
            ATT_MS_EXCH_DIAGNOSTIC_REG_KEY = 131261,

            [Description("msExchDirBrowseFlags")]
            ATT_MS_EXCH_DIR_BROWSE_FLAGS = 1736719005,

            [Description("msExchDirsyncFilters")]
            ATT_MS_EXCH_DIRSYNC_FILTERS = 1736705005,

            [Description("msExchDirsyncSchedule")]
            ATT_MS_EXCH_DIRSYNC_SCHEDULE = 1736705008,

            [Description("msExchDirsyncStyle")]
            ATT_MS_EXCH_DIRSYNC_STYLE = 1736705009,

            [Description("disabledGatewayProxy")]
            ATT_MS_EXCH_DISABLED_GATEWAY_PROXY = 131613,

            [Description("doOABVersion")]
            ATT_MS_EXCH_DO_OAB_VERSION = 131647,

            [Description("domainDefAltRecip")]
            ATT_MS_EXCH_DOMAIN_DEF_ALT_RECIP = 131217,

            [Description("msExchDomainLink")]
            ATT_MS_EXCH_DOMAIN_LINK = 1736704076,

            [Description("domainName")]
            ATT_MS_EXCH_DOMAIN_NAME = 131219,

            [Description("msExchDownGradeMultipartSigned")]
            ATT_MS_EXCH_DOWNGRADE_MULTIPART_SIGNED = 1736715020,

            [Description("dXAAdminCopy")]
            ATT_MS_EXCH_DXA_ADMIN_COPY = 131450,

            [Description("dXAAdminForward")]
            ATT_MS_EXCH_DXA_ADMIN_FORWARD = 131451,

            [Description("dXAAdminUpdate")]
            ATT_MS_EXCH_DXA_ADMIN_UPDATE = 131453,

            [Description("dXAAppendReqCN")]
            ATT_MS_EXCH_DXA_APPEND_REQCN = 131246,

            [Description("dXAConfContainerList")]
            ATT_MS_EXCH_DXA_CONF_CONTAINER_LIST = 131252,

            [Description("dXAConfReqTime")]
            ATT_MS_EXCH_DXA_CONF_REQ_TIME = 131194,

            [Description("dXAConfSeq")]
            ATT_MS_EXCH_DXA_CONF_SEQ = 131256,

            [Description("dXAConfSeqUSN")]
            ATT_MS_EXCH_DXA_CONF_SEQ_USN = 131117,

            [Description("dXAExchangeOptions")]
            ATT_MS_EXCH_DXA_EXCHANGE_OPTIONS = 131431,

            [Description("dXAExportNow")]
            ATT_MS_EXCH_DXA_EXPORT_NOW = 131449,

            [Description("dXAImpSeq")]
            ATT_MS_EXCH_DXA_IMP_SEQ = 131188,

            [Description("dXAImpSeqTime")]
            ATT_MS_EXCH_DXA_IMP_SEQ_TIME = 131189,

            [Description("dXAImpSeqUSN")]
            ATT_MS_EXCH_DXA_IMP_SEQ_USN = 131158,

            [Description("dXAImportNow")]
            ATT_MS_EXCH_DXA_IMPORT_NOW = 131448,

            [Description("dXAInTemplateMap")]
            ATT_MS_EXCH_DXA_IN_TEMPLATE_MAP = 131435,

            [Description("dXALocalAdmin")]
            ATT_MS_EXCH_DXA_LOCAL_ADMIN = 131185,

            [Description("dXANativeAddressType")]
            ATT_MS_EXCH_DXA_NATIVE_ADDRESS_TYPE = 131403,

            [Description("dXAOutTemplateMap")]
            ATT_MS_EXCH_DXA_OUT_TEMPLATE_MAP = 131436,

            [Description("dXAPassword")]
            ATT_MS_EXCH_DXA_PASSWORD = 131377,

            [Description("dXAPrevExchangeOptions")]
            ATT_MS_EXCH_DXA_PREV_EXCHANGE_OPTIONS = 131288,

            [Description("dXAPrevExportNativeOnly")]
            ATT_MS_EXCH_DXA_PREV_EXPORT_NATIVE_ONLY = 131275,

            [Description("dXAPrevInExchangeSensitivity")]
            ATT_MS_EXCH_DXA_PREV_IN_EXCHANGE_SENSITIVITY = 131162,

            [Description("dXAPrevRemoteEntries")]
            ATT_MS_EXCH_DXA_PREV_REMOTE_ENTRIES = 131337,

            [Description("dXAPrevReplicationSensitivity")]
            ATT_MS_EXCH_DXA_PREV_REPLICATION_SENSITIVITY = 131287,

            [Description("dXAPrevTemplateOptions")]
            ATT_MS_EXCH_DXA_PREV_TEMPLATE_OPTIONS = 131467,

            [Description("dXAPrevTypes")]
            ATT_MS_EXCH_DXA_PREV_TYPES = 131289,

            [Description("dXARecipientCP")]
            ATT_MS_EXCH_DXA_RECIPIENT_CP = 131456,

            [Description("dXARemoteClient")]
            ATT_MS_EXCH_DXA_REMOTE_CLIENT = 131184,

            [Description("dXAReqSeq")]
            ATT_MS_EXCH_DXA_REQ_SEQ = 131173,

            [Description("dXAReqSeqTime")]
            ATT_MS_EXCH_DXA_REQ_SEQ_TIME = 131186,

            [Description("dXAReqSeqUSN")]
            ATT_MS_EXCH_DXA_REQ_SEQ_USN = 131254,

            [Description("dXAReqName")]
            ATT_MS_EXCH_DXA_REQNAME = 131518,

            [Description("dXASvrSeq")]
            ATT_MS_EXCH_DXA_SVR_SEQ = 131432,

            [Description("dXASvrSeqTime")]
            ATT_MS_EXCH_DXA_SVR_SEQ_TIME = 131433,

            [Description("dXASvrSeqUSN")]
            ATT_MS_EXCH_DXA_SVR_SEQ_USN = 131196,

            [Description("dXATemplateOptions")]
            ATT_MS_EXCH_DXA_TEMPLATE_OPTIONS = 131430,

            [Description("dXATemplateTimeStamp")]
            ATT_MS_EXCH_DXA_TEMPLATE_TIMESTAMP = 131437,

            [Description("dXATypes")]
            ATT_MS_EXCH_DXA_TYPES = 131191,

            [Description("dXAUnConfContainerList")]
            ATT_MS_EXCH_DXA_UNCONF_CONTAINER_LIST = 131253,

            [Description("msExchEDBFile")]
            ATT_MS_EXCH_EDB_FILE = 1736715001,

            [Description("msExchEDBOffline")]
            ATT_MS_EXCH_EDB_OFFLINE = 1736715007,

            [Description("enableCompatibility")]
            ATT_MS_EXCH_ENABLE_COMPATIBILITY = 131639,

            [Description("enabledAuthorizationPackages")]
            ATT_MS_EXCH_ENABLED_AUTHORIZATION_PACKAGES = 131551,

            [Description("enabledProtocolCfg")]
            ATT_MS_EXCH_ENABLED_PROTOCOL_CFG = 131587,

            [Description("encapsulationMethod")]
            ATT_MS_EXCH_ENCAPSULATION_METHOD = 131520,

            [Description("encrypt")]
            ATT_MS_EXCH_ENCRYPT = 131308,

            [Description("encryptAlgListNA")]
            ATT_MS_EXCH_ENCRYPT_ALG_LIST_NA = 131202,

            [Description("encryptAlgListOther")]
            ATT_MS_EXCH_ENCRYPT_ALG_LIST_OTHER = 131471,

            [Description("encryptAlgSelectedNA")]
            ATT_MS_EXCH_ENCRYPT_ALG_SELECTED_NA = 131473,

            [Description("encryptAlgSelectedOther")]
            ATT_MS_EXCH_ENCRYPT_ALG_SELECTED_OTHER = 131469,

            [Description("msExchESEParamCacheSize")]
            ATT_MS_EXCH_ESE_PARAM_CACHE_SIZE = 1736715002,

            [Description("msExchESEParamCacheSizeMax")]
            ATT_MS_EXCH_ESE_PARAM_CACHE_SIZE_MAX = 1736715003,

            [Description("msExchESEParamCircularLog")]
            ATT_MS_EXCH_ESE_PARAM_CIRCULAR_LOG = 1736715005,

            [Description("msExchESEParamEventSource")]
            ATT_MS_EXCH_ESE_PARAM_EVENT_SOURCE = 1736715008,

            [Description("msExchESEParamLogBuffers")]
            ATT_MS_EXCH_ESE_PARAM_LOG_BUFFERS = 1736715009,

            [Description("msExchESEParamLogCheckpointPeriod")]
            ATT_MS_EXCH_ESE_PARAM_LOG_CHECKPOINT_PERIOD = 1736715010,

            [Description("msExchESEParamLogFilePath")]
            ATT_MS_EXCH_ESE_PARAM_LOG_FILE_PATH = 1736715011,

            [Description("msExchESEParamLogFileSize")]
            ATT_MS_EXCH_ESE_PARAM_LOG_FILE_SIZE = 1736715012,

            [Description("msExchESEParamLogWaitingUserMax")]
            ATT_MS_EXCH_ESE_PARAM_LOG_WAITING_USER_MAX = 1736715013,

            [Description("msExchESEParamMaxOpenTables")]
            ATT_MS_EXCH_ESE_PARAM_MAX_OPEN_TABLES = 1736715014,

            [Description("msExchESEParamMaxSessions")]
            ATT_MS_EXCH_ESE_PARAM_MAX_SESSIONS = 1736715015,

            [Description("msExchESEParamMaxVerPages")]
            ATT_MS_EXCH_ESE_PARAM_MAX_VER_PAGES = 1736715017,

            [Description("msExchESEParamPreferredMaxOpenTables")]
            ATT_MS_EXCH_ESE_PARAM_PREFERRED_MAX_OPEN_TABLES = 1736715018,

            [Description("msExchESEParamPreferredVerPages")]
            ATT_MS_EXCH_ESE_PARAM_PREFERRED_VER_PAGES = 1736715019,

            [Description("msExchESEParamSystemPath")]
            ATT_MS_EXCH_ESE_PARAM_SYSTEM_PATH = 1736715022,

            [Description("msExchESEParamTempPath")]
            ATT_MS_EXCH_ESE_PARAM_TEMP_PATH = 1736715023,

            [Description("msExchESEParamWaitLogFlush")]
            ATT_MS_EXCH_ESE_PARAM_WAIT_LOG_FLUSH = 1736715016,

            [Description("msExchESEParamZeroDatabaseDuringBackup")]
            ATT_MS_EXCH_ESE_PARAM_ZERO_DATABASE_DURING_BACKUP = 1736715026,

            [Description("expandDLsLocally")]
            ATT_MS_EXCH_EXPAND_DLS_LOCALLY = 131273,

            [Description("exportContainers")]
            ATT_MS_EXCH_EXPORT_CONTAINERS = 131183,

            [Description("exportCustomRecipients")]
            ATT_MS_EXCH_EXPORT_CUSTOM_RECIPIENTS = 131379,

            [Description("msExchExportDLs")]
            ATT_MS_EXCH_EXPORT_DLS = 1736705004,

            [Description("fileVersion")]
            ATT_MS_EXCH_FILE_VERSION = 131250,

            [Description("filterLocalAddresses")]
            ATT_MS_EXCH_FILTER_LOCAL_ADDRESSES = 131116,

            [Description("msExchFirstInstance")]
            ATT_MS_EXCH_FIRST_INSTANCE = 1736715053,

            [Description("gatewayLocalCred")]
            ATT_MS_EXCH_GATEWAY_LOCAL_CRED = 131109,

            [Description("gatewayLocalDesig")]
            ATT_MS_EXCH_GATEWAY_LOCAL_DESIG = 131101,

            [Description("gatewayProxy")]
            ATT_MS_EXCH_GATEWAY_PROXY = 131374,

            [Description("gatewayRoutingTree")]
            ATT_MS_EXCH_GATEWAY_ROUTING_TREE = 131239,

            [Description("msExchGracePeriodAfter")]
            ATT_MS_EXCH_GRACE_PERIOD_AFTER = 1736713003,

            [Description("msExchGracePeriodPrior")]
            ATT_MS_EXCH_GRACE_PERIOD_PRIOR = 1736713002,

            [Description("gWARTLastModified")]
            ATT_MS_EXCH_GWART_LAST_MODIFIED = 131332,

            [Description("msExchHomePublicMDB")]
            ATT_MS_EXCH_HOME_PUBLIC_MDB = 1736715044,

            [Description("hTTPPubABAttributes")]
            ATT_MS_EXCH_HTTP_PUB_AB_ATTRIBUTES = 131588,

            [Description("hTTPPubGAL")]
            ATT_MS_EXCH_HTTP_PUB_GAL = 131574,

            [Description("hTTPPubGALLimit")]
            ATT_MS_EXCH_HTTP_PUB_GAL_LIMIT = 131575,

            [Description("hTTPPubPF")]
            ATT_MS_EXCH_HTTP_PUB_PF = 131577,

            [Description("hTTPServers")]
            ATT_MS_EXCH_HTTP_SERVERS = 131589,

            [Description("msExchIFSPrivateEnabled")]
            ATT_MS_EXCH_IFS_PRIVATE_ENABLED = 1736715029,

            [Description("msExchIFSPrivateName")]
            ATT_MS_EXCH_IFS_PRIVATE_NAME = 1736715033,

            [Description("msExchIFSPublicEnabled")]
            ATT_MS_EXCH_IFS_PUBLIC_ENABLED = 1736715050,

            [Description("msExchIFSPublicName")]
            ATT_MS_EXCH_IFS_PUBLIC_NAME = 1736715051,

            [Description("msExchIMDBLogPath")]
            ATT_MS_EXCH_IM_DB_LOG_PATH = 1736711016,

            [Description("msExchIMDBPath")]
            ATT_MS_EXCH_IM_DB_PATH = 1736711015,

            [Description("msExchIMServerHostsUsers")]
            ATT_MS_EXCH_IM_SERVER_HOSTS_USERS = 1736711025,

            [Description("msExchIMServerIISId")]
            ATT_MS_EXCH_IM_SERVER_IIS_ID = 1736711023,

            [Description("msExchIMServerName")]
            ATT_MS_EXCH_IM_SERVER_NAME = 1736711024,

            [Description("importContainer")]
            ATT_MS_EXCH_IMPORT_CONTAINER = 131182,

            [Description("msExchIncomingConnectionTimeout")]
            ATT_MS_EXCH_INCOMING_CONNECTION_TIMEOUT = 1736706015,

            [Description("incomingMsgSizeLimit")]
            ATT_MS_EXCH_INCOMING_MSG_SIZE_LIMIT = 131563,

            [Description("iNSAdmin")]
            ATT_MS_EXCH_INSADMIN = 131615,

            [Description("msExchInstallPath")]
            ATT_MS_EXCH_INSTALL_PATH = 1030521699,

            [Description("msExchInternetName")]
            ATT_MS_EXCH_INTERNET_NAME = 1736713019,

            [Description("msExchIPAddress")]
            ATT_MS_EXCH_IP_ADDRESS = 1736709050,

            [Description("msExchIPSecurity")]
            ATT_MS_EXCH_IP_SECURITY = 1736706013,

            [Description("kCCStatus")]
            ATT_MS_EXCH_KCC_STATUS = 131309,

            [Description("lDAPSearchCfg")]
            ATT_MS_EXCH_LDAP_SEARCH_CFG = 131624,

            [Description("lineWrap")]
            ATT_MS_EXCH_LINE_WRAP = 131521,

            [Description("msExchListPublic")]
            ATT_MS_EXCH_LIST_PUBLIC = 1736713011,

            [Description("listPublicFolders")]
            ATT_MS_EXCH_LIST_PUBLIC_FOLDERS = 131664,

            [Description("localInitialTurn")]
            ATT_MS_EXCH_LOCAL_INITIAL_TURN = 131111,

            [Description("msExchLocalName")]
            ATT_MS_EXCH_LOCAL_NAME = 1736713017,

            [Description("msExchLocales")]
            ATT_MS_EXCH_LOCALES = 1030521697,

            [Description("logFilename")]
            ATT_MS_EXCH_LOG_FILENAME = 131264,

            [Description("logRolloverInterval")]
            ATT_MS_EXCH_LOG_ROLLOVER_INTERVAL = 131420,

            [Description("msExchLogType")]
            ATT_MS_EXCH_LOG_TYPE = 1736706005,

            [Description("msExchLogonMethod")]
            ATT_MS_EXCH_LOGON_METHOD = 1736719002,

            [Description("msExchMaxConnections")]
            ATT_MS_EXCH_MAX_CONNECTIONS = 1736713013,

            [Description("msExchMaxIncomingConnections")]
            ATT_MS_EXCH_MAX_INCOMING_CONNECTIONS = 1736706004,

            [Description("msExchMaxPoolThreads")]
            ATT_MS_EXCH_MAX_POOL_THREADS = 1736715041,

            [Description("msExchMaxStorageGroups")]
            ATT_MS_EXCH_MAX_STORAGE_GROUPS = 1736715027,

            [Description("msExchMaxStoresPerGroup")]
            ATT_MS_EXCH_MAX_STORES_PER_GROUP = 1736715028,

            [Description("msExchMaxThreads")]
            ATT_MS_EXCH_MAX_THREADS = 1736715042,

            [Description("maximumObjectID")]
            ATT_MS_EXCH_MAXIMUM_OBJECT_ID = 131530,

            [Description("msExchMaximumRecurringInstances")]
            ATT_MS_EXCH_MAXIMUM_RECURRING_INSTANCES = 1736714014,

            [Description("msExchMaximumRecurringInstancesMonths")]
            ATT_MS_EXCH_MAXIMUM_RECURRING_INSTANCES_MONTHS = 1736714015,

            [Description("mDBBackoffInterval")]
            ATT_MS_EXCH_MDB_BACKOFF_INTERVAL = 131144,

            [Description("mDBMsgTimeOutPeriod")]
            ATT_MS_EXCH_MDB_MSG_TIME_OUT_PERIOD = 131136,

            [Description("mDBUnreadLimit")]
            ATT_MS_EXCH_MDB_UNREAD_LIMIT = 131141,

            [Description("messageSizeLimit")]
            ATT_MS_EXCH_MESSAGE_SIZE_LIMIT = 131172,

            [Description("msExchMessageTrackLogFilter")]
            ATT_MS_EXCH_MESSAGE_TRACK_LOG_FILTER = 1030521681,

            [Description("messageTrackingEnabled")]
            ATT_MS_EXCH_MESSAGE_TRACKING_ENABLED = 131525,

            [Description("msExchMimeTypes")]
            ATT_MS_EXCH_MIME_TYPES = 1736704550,

            [Description("msExchMinimumThreads")]
            ATT_MS_EXCH_MINIMUM_THREADS = 1736715043,

            [Description("msExchMixedMode")]
            ATT_MS_EXCH_MIXED_MODE = 1030521702,

            [Description("monitorClock")]
            ATT_MS_EXCH_MONITOR_CLOCK = 131235,

            [Description("monitorServers")]
            ATT_MS_EXCH_MONITOR_SERVERS = 131228,

            [Description("monitorServices")]
            ATT_MS_EXCH_MONITOR_SERVICES = 131232,

            [Description("monitoredConfigurations")]
            ATT_MS_EXCH_MONITORED_CONFIGURATIONS = 131270,

            [Description("monitoredServers")]
            ATT_MS_EXCH_MONITORED_SERVERS = 131251,

            [Description("monitoredServices")]
            ATT_MS_EXCH_MONITORED_SERVICES = 131271,

            [Description("monitoringAlertDelay")]
            ATT_MS_EXCH_MONITORING_ALERT_DELAY = 131230,

            [Description("monitoringAlertUnits")]
            ATT_MS_EXCH_MONITORING_ALERT_UNITS = 131129,

            [Description("monitoringAvailabilityStyle")]
            ATT_MS_EXCH_MONITORING_AVAILABILITY_STYLE = 131522,

            [Description("monitoringAvailabilityWindow")]
            ATT_MS_EXCH_MONITORING_AVAILABILITY_WINDOW = 131272,

            [Description("monitoringCachedViaMail")]
            ATT_MS_EXCH_MONITORING_CACHED_VIA_MAIL = 131268,

            [Description("monitoringCachedViaRPC")]
            ATT_MS_EXCH_MONITORING_CACHED_VIA_RPC = 131269,

            [Description("monitoringEscalationProcedure")]
            ATT_MS_EXCH_MONITORING_ESCALATION_PROCEDURE = 131260,

            [Description("monitoringHotsitePollInterval")]
            ATT_MS_EXCH_MONITORING_HOTSITE_POLL_INTERVAL = 131258,

            [Description("monitoringHotsitePollUnits")]
            ATT_MS_EXCH_MONITORING_HOTSITE_POLL_UNITS = 131159,

            [Description("monitoringMailUpdateInterval")]
            ATT_MS_EXCH_MONITORING_MAIL_UPDATE_INTERVAL = 131267,

            [Description("monitoringMailUpdateUnits")]
            ATT_MS_EXCH_MONITORING_MAIL_UPDATE_UNITS = 131165,

            [Description("monitoringNormalPollInterval")]
            ATT_MS_EXCH_MONITORING_NORMAL_POLL_INTERVAL = 131259,

            [Description("monitoringNormalPollUnits")]
            ATT_MS_EXCH_MONITORING_NORMAL_POLL_UNITS = 131160,

            [Description("monitoringRecipients")]
            ATT_MS_EXCH_MONITORING_RECIPIENTS = 131231,

            [Description("monitoringRecipientsNDR")]
            ATT_MS_EXCH_MONITORING_RECIPIENTS_NDR = 131459,

            [Description("monitoringRPCUpdateInterval")]
            ATT_MS_EXCH_MONITORING_RPC_UPDATE_INTERVAL = 131164,

            [Description("monitoringRPCUpdateUnits")]
            ATT_MS_EXCH_MONITORING_RPC_UPDATE_UNITS = 131161,

            [Description("monitoringWarningDelay")]
            ATT_MS_EXCH_MONITORING_WARNING_DELAY = 131229,

            [Description("monitoringWarningUnits")]
            ATT_MS_EXCH_MONITORING_WARNING_UNITS = 131128,

            [Description("mTALocalCred")]
            ATT_MS_EXCH_MTA_LOCAL_CRED = 131342,

            [Description("mTALocalDesig")]
            ATT_MS_EXCH_MTA_LOCAL_DESIG = 131343,

            [Description("nAddress")]
            ATT_MS_EXCH_N_ADDRESS = 131354,

            [Description("nAddressType")]
            ATT_MS_EXCH_N_ADDRESS_TYPE = 131294,

            [Description("msExchNotesConnectorMailbox")]
            ATT_MS_EXCH_NOTES_CONNECTOR_MAILBOX = 1736705014,

            [Description("msExchNotesExcludeGroups")]
            ATT_MS_EXCH_NOTES_EXCLUDE_GROUPS = 1736705022,

            [Description("msExchNotesExportGroups")]
            ATT_MS_EXCH_NOTES_EXPORT_GROUPS = 1736705021,

            [Description("msExchNotesForeignDomain")]
            ATT_MS_EXCH_NOTES_FOREIGN_DOMAIN = 1736705012,

            [Description("msExchNotesLetterhead")]
            ATT_MS_EXCH_NOTES_LETTERHEAD = 1736705015,

            [Description("msExchNotesNotesINI")]
            ATT_MS_EXCH_NOTES_NOTES_INI = 1736705017,

            [Description("msExchNotesNotesLinks")]
            ATT_MS_EXCH_NOTES_NOTES_LINKS = 1736705016,

            [Description("msExchNotesNotesServer")]
            ATT_MS_EXCH_NOTES_NOTES_SERVER = 1736705011,

            [Description("msExchNotesRoutableDomains")]
            ATT_MS_EXCH_NOTES_ROUTABLE_DOMAINS = 1736705023,

            [Description("msExchNotesRtrMailbox")]
            ATT_MS_EXCH_NOTES_RTR_MAILBOX = 1736705013,

            [Description("msExchNotesSourceBooks")]
            ATT_MS_EXCH_NOTES_SOURCE_BOOKS = 1736705020,

            [Description("msExchNotesTargetBook")]
            ATT_MS_EXCH_NOTES_TARGET_BOOK = 1736705018,

            [Description("msExchNotesTargetBooks")]
            ATT_MS_EXCH_NOTES_TARGET_BOOKS = 1736705019,

            [Description("msExchNTAuthenticationProviders")]
            ATT_MS_EXCH_NT_AUTHENTICATION_PROVIDERS = 1736706009,

            [Description("numOfOpenRetries")]
            ATT_MS_EXCH_NUM_OF_OPEN_RETRIES = 131220,

            [Description("numOfTransferRetries")]
            ATT_MS_EXCH_NUM_OF_TRANSFER_RETRIES = 131206,

            [Description("msExchOABDefault")]
            ATT_MS_EXCH_OAB_DEFAULT = 1736704067,

            [Description("msExchOABFolder")]
            ATT_MS_EXCH_OAB_FOLDER = 1736704068,

            [Description("objViewContainers")]
            ATT_MS_EXCH_OBJ_VIEW_CONTAINERS = 131617,

            [Description("offLineABContainers")]
            ATT_MS_EXCH_OFF_LINE_AB_CONTAINERS = 131463,

            [Description("offLineABSchedule")]
            ATT_MS_EXCH_OFF_LINE_AB_SCHEDULE = 131461,

            [Description("offLineABServer")]
            ATT_MS_EXCH_OFF_LINE_AB_SERVER = 131464,

            [Description("offLineABStyle")]
            ATT_MS_EXCH_OFF_LINE_AB_STYLE = 131462,

            [Description("openRetryInterval")]
            ATT_MS_EXCH_OPEN_RETRY_INTERVAL = 131215,

            [Description("outgoingMsgSizeLimit")]
            ATT_MS_EXCH_OUTGOING_MSG_SIZE_LIMIT = 131562,

            [Description("msExchOverallAgeLimit")]
            ATT_MS_EXCH_OVERALL_AGE_LIMIT = 1736715055,

            [Description("msExchOwningOrg")]
            ATT_MS_EXCH_OWNING_ORG = 1736715030,

            [Description("msExchOwningServer")]
            ATT_MS_EXCH_OWNING_SERVER = 1736715004,

            [Description("pSelector")]
            ATT_MS_EXCH_P_SELECTOR = 131357,

            [Description("pSelectorInbound")]
            ATT_MS_EXCH_P_SELECTOR_INBOUND = 131124,

            [Description("msExchPartnerCP")]
            ATT_MS_EXCH_PARTNER_CP = 1736705007,

            [Description("msExchPartnerLanguage")]
            ATT_MS_EXCH_PARTNER_LANGUAGE = 1736705006,

            [Description("pFContacts")]
            ATT_MS_EXCH_PF_CONTACTS = 131147,

            [Description("msExchPolicyDefault")]
            ATT_MS_EXCH_POLICY_DEFAULT = 1030521687,

            [Description("msExchPolicyLockDown")]
            ATT_MS_EXCH_POLICY_LOCKDOWN = 1030521688,

            [Description("msExchPollInterval")]
            ATT_MS_EXCH_POLL_INTERVAL = 1736704058,

            [Description("portNumber")]
            ATT_MS_EXCH_PORT_NUMBER = 131599,

            [Description("preserveInternetContent")]
            ATT_MS_EXCH_PRESERVE_INTERNET_CONTENT = 131628,

            [Description("pRMD")]
            ATT_MS_EXCH_PRMD = 131296,

            [Description("msExchProxyGenServer")]
            ATT_MS_EXCH_PROXY_GEN_SERVER = 1030521693,

            [Description("proxyGeneratorDLL")]
            ATT_MS_EXCH_PROXY_GENERATOR_DLL = 131400,

            [Description("msExchProxyName")]
            ATT_MS_EXCH_PROXY_NAME = 1736713018,

            [Description("msExchQueuingMDB")]
            ATT_MS_EXCH_QUEUING_MDB = 1736715054,

            [Description("quotaNotificationSchedule")]
            ATT_MS_EXCH_QUOTA_NOTIFICATION_SCHEDULE = 131170,

            [Description("quotaNotificationStyle")]
            ATT_MS_EXCH_QUOTA_NOTIFICATION_STYLE = 131460,

            [Description("rASCallbackNumber")]
            ATT_MS_EXCH_RAS_CALLBACK_NUMBER = 131387,

            [Description("rASPhoneNumber")]
            ATT_MS_EXCH_RAS_PHONE_NUMBER = 131386,

            [Description("rASPhonebookEntryName")]
            ATT_MS_EXCH_RAS_PHONEBOOK_ENTRY_NAME = 131385,

            [Description("rASRemoteSRVRName")]
            ATT_MS_EXCH_RAS_REMOTE_SRVR_NAME = 131150,

            [Description("msExchRecovery")]
            ATT_MS_EXCH_RECOVERY = 1736715046,

            [Description("referralList")]
            ATT_MS_EXCH_REFERRAL_LIST = 131582,

            [Description("msExchReplicationMsgSize")]
            ATT_MS_EXCH_REPLICATION_MSG_SIZE = 1736715047,

            [Description("msExchReplicationSchedule")]
            ATT_MS_EXCH_REPLICATION_SCHEDULE = 1736715048,

            [Description("msExchReplicationStyle")]
            ATT_MS_EXCH_REPLICATION_STYLE = 1736715049,

            [Description("reqSeq")]
            ATT_MS_EXCH_REQ_SEQ = 131245,

            [Description("requireSSL")]
            ATT_MS_EXCH_REQUIRE_SSL = 131632,

            [Description("returnExactMsgSize")]
            ATT_MS_EXCH_RETURN_EXACT_MSG_SIZE = 131666,

            [Description("ridServer")]
            ATT_MS_EXCH_RID_SERVER = 131418,

            [Description("msExchRoleIncludes")]
            ATT_MS_EXCH_ROLE_INCLUDES = 1030521700,

            [Description("msExchRoleLocalizedNames")]
            ATT_MS_EXCH_ROLE_LOCALIZED_NAMES = 1030521701,

            [Description("msExchRoleRights")]
            ATT_MS_EXCH_ROLE_RIGHTS = 1030521698,

            [Description("rootNewsgroupsFolderID")]
            ATT_MS_EXCH_ROOT_NEWSGROUPS_FOLDER_ID = 131596,

            [Description("msExchRoutingAcceptMessageType")]
            ATT_MS_EXCH_ROUTING_ACCEPT_MESSAGE_TYPE = 1736716517,

            [Description("msExchRoutingDisallowPriority")]
            ATT_MS_EXCH_ROUTING_DISALLOW_PRIORITY = 1736716529,

            [Description("msExchRoutingDisplaySenderEnabled")]
            ATT_MS_EXCH_ROUTING_DISPLAY_SENDER_ENABLED = 1736716519,

            [Description("msExchRoutingEnabled")]
            ATT_MS_EXCH_ROUTING_ENABLED = 1736716528,

            [Description("routingList")]
            ATT_MS_EXCH_ROUTING_LIST = 131426,

            [Description("msExchRoutingMasterDN")]
            ATT_MS_EXCH_ROUTING_MASTER_DN = 1736716505,

            [Description("msExchRoutingOversizedSchedule")]
            ATT_MS_EXCH_ROUTING_OVERSIZED_SCHEDULE = 1736716520,

            [Description("msExchRoutingOversizedStyle")]
            ATT_MS_EXCH_ROUTING_OVERSIZED_STYLE = 1736716521,

            [Description("msExchRoutingTriggeredSchedule")]
            ATT_MS_EXCH_ROUTING_TRIGGERED_SCHEDULE = 1736716526,

            [Description("msExchRoutingTriggeredStyle")]
            ATT_MS_EXCH_ROUTING_TRIGGERED_STYLE = 1736716525,

            [Description("rTSCheckpointSize")]
            ATT_MS_EXCH_RTS_CHECKPOINT_SIZE = 131224,

            [Description("rTSRecoveryTimeout")]
            ATT_MS_EXCH_RTS_RECOVERY_TIMEOUT = 131223,

            [Description("rTSWindowSize")]
            ATT_MS_EXCH_RTS_WINDOW_SIZE = 131225,

            [Description("runsOn")]
            ATT_MS_EXCH_RUNS_ON = 131257,

            [Description("msExchSaslLogonDomain")]
            ATT_MS_EXCH_SASL_LOGON_DOMAIN = 1736706008,

            [Description("msExchScopeMask")]
            ATT_MS_EXCH_SCOPE_MASK = 1736713014,

            [Description("securityPolicy")]
            ATT_MS_EXCH_SECURITY_POLICY = 131661,

            [Description("sendEMailMessage")]
            ATT_MS_EXCH_SEND_EMAIL_MESSAGE = 131638,

            [Description("sendTNEF")]
            ATT_MS_EXCH_SEND_TNEF = 131564,

            [Description("msExchServerAutoStart")]
            ATT_MS_EXCH_SERVER_AUTO_START = 1736706007,

            [Description("msExchServerRole")]
            ATT_MS_EXCH_SERVER_ROLE = 1736719006,

            [Description("serviceActionFirst")]
            ATT_MS_EXCH_SERVICE_ACTION_FIRST = 131233,

            [Description("serviceActionOther")]
            ATT_MS_EXCH_SERVICE_ACTION_OTHER = 131131,

            [Description("serviceActionSecond")]
            ATT_MS_EXCH_SERVICE_ACTION_SECOND = 131132,

            [Description("serviceRestartDelay")]
            ATT_MS_EXCH_SERVICE_RESTART_DELAY = 131234,

            [Description("serviceRestartMessage")]
            ATT_MS_EXCH_SERVICE_RESTART_MESSAGE = 131130,

            [Description("sessionDisconnectTimer")]
            ATT_MS_EXCH_SESSION_DISCONNECT_TIMER = 131226,

            [Description("siteFolderGUID")]
            ATT_MS_EXCH_SITE_FOLDER_GUID = 131528,

            [Description("siteFolderServer")]
            ATT_MS_EXCH_SITE_FOLDER_SERVER = 131529,

            [Description("siteProxySpace")]
            ATT_MS_EXCH_SITE_PROXY_SPACE = 131457,

            [Description("msExchSLVFile")]
            ATT_MS_EXCH_SLV_FILE = 1736715036,

            [Description("sMIMEAlgListNA")]
            ATT_MS_EXCH_SMIME_ALG_LIST_NA = 131640,

            [Description("sMIMEAlgListOther")]
            ATT_MS_EXCH_SMIME_ALG_LIST_OTHER = 131641,

            [Description("sMIMEAlgSelectedNA")]
            ATT_MS_EXCH_SMIME_ALG_SELECTED_NA = 131642,

            [Description("sMIMEAlgSelectedOther")]
            ATT_MS_EXCH_SMIME_ALG_SELECTED_OTHER = 131643,

            [Description("msExchSmtpAuthorizedTRNAccounts")]
            ATT_MS_EXCH_SMTP_AUTHORIZED_TRN_ACCOUNTS = 1736709047,

            [Description("msExchSmtpBadMailDirectory")]
            ATT_MS_EXCH_SMTP_BAD_MAIL_DIRECTORY = 1736709025,

            [Description("msExchSmtpDoMasquerade")]
            ATT_MS_EXCH_SMTP_DO_MASQUERADE = 1736709022,

            [Description("msExchSmtpDomainString")]
            ATT_MS_EXCH_SMTP_DOMAIN_STRING = 1736709033,

            [Description("msExchSmtpDropDirectory")]
            ATT_MS_EXCH_SMTP_DROP_DIRECTORY = 1736709032,

            [Description("msExchSmtpDsDataDirectory")]
            ATT_MS_EXCH_SMTP_DS_DATA_DIRECTORY = 1736709036,

            [Description("msExchSmtpDsDefaultMailRoot")]
            ATT_MS_EXCH_SMTP_DS_DEFAULT_MAIL_ROOT = 1736709037,

            [Description("msExchSmtpDsDomain")]
            ATT_MS_EXCH_SMTP_DS_DOMAIN = 1736709038,

            [Description("msExchSmtpDsFlags")]
            ATT_MS_EXCH_SMTP_DS_FLAGS = 1736709049,

            [Description("msExchSmtpDsHost")]
            ATT_MS_EXCH_SMTP_DS_HOST = 1736709042,

            [Description("msExchSmtpDsPort")]
            ATT_MS_EXCH_SMTP_DS_PORT = 1736709017,

            [Description("msExchSmtpEnableLdapRouting")]
            ATT_MS_EXCH_SMTP_ENABLE_LDAP_ROUTING = 1736709019,

            [Description("msExchSmtpFullyQualifiedDomainName")]
            ATT_MS_EXCH_SMTP_FULLY_QUALIFIED_DOMAIN_NAME = 1736709029,

            [Description("msExchSmtpInboundCommandSupportOptions")]
            ATT_MS_EXCH_SMTP_INBOUND_COMMAND_SUPPORT_OPTIONS = 1736709018,

            [Description("msExchSmtpLdapAccount")]
            ATT_MS_EXCH_SMTP_LDAP_ACCOUNT = 1736709044,

            [Description("msExchSmtpLdapBindType")]
            ATT_MS_EXCH_SMTP_LDAP_BIND_TYPE = 1736709040,

            [Description("msExchSmtpLdapNamingContext")]
            ATT_MS_EXCH_SMTP_LDAP_NAMING_CONTEXT = 1736709043,

            [Description("msExchSmtpLdapPassword")]
            ATT_MS_EXCH_SMTP_LDAP_PASSWORD = 1736709045,

            [Description("msExchSmtpLdapSchemaType")]
            ATT_MS_EXCH_SMTP_LDAP_SCHEMA_TYPE = 1736709041,

            [Description("msExchSmtpLocalQueueDelayNotification")]
            ATT_MS_EXCH_SMTP_LOCAL_QUEUE_DELAY_NOTIFICATION = 1736709011,

            [Description("msExchSmtpLocalQueueExpirationTimeout")]
            ATT_MS_EXCH_SMTP_LOCAL_QUEUE_EXPIRATION_TIMEOUT = 1736709010,

            [Description("msExchSmtpMasqueradeDomain")]
            ATT_MS_EXCH_SMTP_MASQUERADE_DOMAIN = 1736709026,

            [Description("msExchSmtpMaxHopCount")]
            ATT_MS_EXCH_SMTP_MAX_HOP_COUNT = 1736709006,

            [Description("msExchSmtpMaxMessageSize")]
            ATT_MS_EXCH_SMTP_MAX_MESSAGE_SIZE = 1736709007,

            [Description("msExchSmtpMaxOutboundMsgPerDomain")]
            ATT_MS_EXCH_SMTP_MAX_OUTBOUND_MSG_PER_DOMAIN = 1736709015,

            [Description("msExchSmtpMaxOutboundMsgPerDomainFlag")]
            ATT_MS_EXCH_SMTP_MAX_OUTBOUND_MSG_PER_DOMAIN_FLAG = 1736709023,

            [Description("msExchSmtpMaxOutgoingConnections")]
            ATT_MS_EXCH_SMTP_MAX_OUTGOING_CONNECTIONS = 1736709001,

            [Description("msExchSmtpMaxOutgoingConnectionsPerDomain")]
            ATT_MS_EXCH_SMTP_MAX_OUTGOING_CONNECTIONS_PER_DOMAIN = 1736709003,

            [Description("msExchSmtpMaxRecipients")]
            ATT_MS_EXCH_SMTP_MAX_RECIPIENTS = 1736709009,

            [Description("msExchSmtpMaxSessionSize")]
            ATT_MS_EXCH_SMTP_MAX_SESSION_SIZE = 1736709008,

            [Description("msExchSmtpOutboundSecurityFlag")]
            ATT_MS_EXCH_SMTP_OUTBOUND_SECURITY_FLAG = 1736709016,

            [Description("msExchSmtpOutboundSecurityPassword")]
            ATT_MS_EXCH_SMTP_OUTBOUND_SECURITY_PASSWORD = 1736709035,

            [Description("msExchSmtpOutboundSecurityUserName")]
            ATT_MS_EXCH_SMTP_OUTBOUND_SECURITY_USER_NAME = 1736709034,

            [Description("msExchSmtpOutgoingConnectionTimeout")]
            ATT_MS_EXCH_SMTP_OUTGOING_CONNECTION_TIMEOUT = 1736709002,

            [Description("msExchSmtpOutgoingPort")]
            ATT_MS_EXCH_SMTP_OUTGOING_PORT = 1736709004,

            [Description("msExchSmtpOutgoingSecurePort")]
            ATT_MS_EXCH_SMTP_OUTGOING_SECURE_PORT = 1736709005,

            [Description("msExchSmtpPerformReverseDnsLookup")]
            ATT_MS_EXCH_SMTP_PERFORM_REVERSE_DNS_LOOKUP = 1736709021,

            [Description("msExchSmtpPickupDirectory")]
            ATT_MS_EXCH_SMTP_PICKUP_DIRECTORY = 1736709030,

            [Description("msExchSmtpQueueDirectory")]
            ATT_MS_EXCH_SMTP_QUEUE_DIRECTORY = 1736709031,

            [Description("msExchSmtpRelayForAuth")]
            ATT_MS_EXCH_SMTP_RELAY_FOR_AUTH = 1736709020,

            [Description("msExchSmtpRelayIpList")]
            ATT_MS_EXCH_SMTP_RELAY_IP_LIST = 1736709048,

            [Description("msExchSmtpRemoteQueueDelayNotification")]
            ATT_MS_EXCH_SMTP_REMOTE_QUEUE_DELAY_NOTIFICATION = 1736709013,

            [Description("msExchSmtpRemoteQueueExpirationTimeout")]
            ATT_MS_EXCH_SMTP_REMOTE_QUEUE_EXPIRATION_TIMEOUT = 1736709012,

            [Description("msExchSmtpRemoteQueueRetries")]
            ATT_MS_EXCH_SMTP_REMOTE_QUEUE_RETRIES = 1736709046,

            [Description("msExchSmtpRoutingTableType")]
            ATT_MS_EXCH_SMTP_ROUTING_TABLE_TYPE = 1736709039,

            [Description("msExchSmtpSendBadmailTo")]
            ATT_MS_EXCH_SMTP_SEND_BADMAIL_TO = 1736709028,

            [Description("msExchSmtpSendNDRTo")]
            ATT_MS_EXCH_SMTP_SEND_NDR_TO = 1736709027,

            [Description("msExchSmtpSmartHost")]
            ATT_MS_EXCH_SMTP_SMART_HOST = 1736709024,

            [Description("msExchSmtpSmartHostType")]
            ATT_MS_EXCH_SMTP_SMART_HOST_TYPE = 1736709014,

            [Description("msExchSourceBHAddress")]
            ATT_MS_EXCH_SOURCE_BH_ADDRESS = 1736716509,

            [Description("spaceLastComputed")]
            ATT_MS_EXCH_SPACE_LAST_COMPUTED = 131458,

            [Description("supportSMIMESignatures")]
            ATT_MS_EXCH_SUPPORT_SMIME_SIGNATURES = 131662,

            [Description("tSelector")]
            ATT_MS_EXCH_T_SELECTOR = 131355,

            [Description("targetMTAs")]
            ATT_MS_EXCH_TARGET_MTAS = 131331,

            [Description("tempAssocThreshold")]
            ATT_MS_EXCH_TEMP_ASSOC_THRESHOLD = 131401,

            [Description("msExchTemplateRDNs")]
            ATT_MS_EXCH_TEMPLATE_RDNS = 1736704065,

            [Description("msExchTrackDuplicates")]
            ATT_MS_EXCH_TRACK_DUPLICATES = 1736715006,

            [Description("trackingLogPathName")]
            ATT_MS_EXCH_TRACKING_LOG_PATH_NAME = 131419,

            [Description("transRetryMins")]
            ATT_MS_EXCH_TRANS_RETRY_MINS = 131291,

            [Description("transTimeoutMins")]
            ATT_MS_EXCH_TRANS_TIMEOUT_MINS = 131292,

            [Description("transferRetryInterval")]
            ATT_MS_EXCH_TRANSFER_RETRY_INTERVAL = 131205,

            [Description("transferTimeoutNonUrgent")]
            ATT_MS_EXCH_TRANSFER_TIMEOUT_NON_URGENT = 131208,

            [Description("transferTimeoutNormal")]
            ATT_MS_EXCH_TRANSFER_TIMEOUT_NORMAL = 131209,

            [Description("transferTimeoutUrgent")]
            ATT_MS_EXCH_TRANSFER_TIMEOUT_URGENT = 131214,

            [Description("translationTableUsed")]
            ATT_MS_EXCH_TRANSLATION_TABLE_USED = 131468,

            [Description("transportExpeditedData")]
            ATT_MS_EXCH_TRANSPORT_EXPEDITED_DATA = 131222,

            [Description("msExchTrkLogCleaningInterval")]
            ATT_MS_EXCH_TRK_LOG_CLEANING_INTERVAL = 1030521696,

            [Description("msExchTurfList")]
            ATT_MS_EXCH_TURF_LIST = 1736709051,

            [Description("turnRequestThreshold")]
            ATT_MS_EXCH_TURN_REQUEST_THRESHOLD = 131110,

            [Description("twoWayAlternateFacility")]
            ATT_MS_EXCH_TWO_WAY_ALTERNATE_FACILITY = 131112,

            [Description("msExchUNCPassword")]
            ATT_MS_EXCH_UNC_PASSWORD = 1736719004,

            [Description("msExchUNCUsername")]
            ATT_MS_EXCH_UNC_USERNAME = 1736719003,

            [Description("useSiteValues")]
            ATT_MS_EXCH_USE_SITE_VALUES = 131550,

            [Description("usenetSiteName")]
            ATT_MS_EXCH_USENET_SITE_NAME = 131556,

            [Description("msExchVisibilityMask")]
            ATT_MS_EXCH_VISIBILITY_MASK = 1736713016,

            [Description("msExchWebAccessName")]
            ATT_MS_EXCH_WEB_ACCESS_NAME = 1736719007,

            [Description("x25CallUserDataIncoming")]
            ATT_MS_EXCH_X25_CALL_USER_DATA_INCOMING = 131388,

            [Description("x25CallUserDataOutgoing")]
            ATT_MS_EXCH_X25_CALL_USER_DATA_OUTGOING = 131389,

            [Description("x25FacilitiesDataIncoming")]
            ATT_MS_EXCH_X25_FACILITIES_DATA_INCOMING = 131390,

            [Description("x25FacilitiesDataOutgoing")]
            ATT_MS_EXCH_X25_FACILITIES_DATA_OUTGOING = 131391,

            [Description("x25LeasedLinePort")]
            ATT_MS_EXCH_X25_LEASED_LINE_PORT = 131393,

            [Description("x25LeasedOrSwitched")]
            ATT_MS_EXCH_X25_LEASED_OR_SWITCHED = 131444,

            [Description("x25RemoteMTAPhone")]
            ATT_MS_EXCH_X25_REMOTE_MTA_PHONE = 131445,

            [Description("x400AttachmentType")]
            ATT_MS_EXCH_X400_ATTACHMENT_TYPE = 131171,

            [Description("x400SelectorSyntax")]
            ATT_MS_EXCH_X400_SELECTOR_SYNTAX = 131515,

            [Description("x500RDN")]
            ATT_MS_EXCH_X500_RDN = 131580,

            [Description("xMITTimeoutNonUrgent")]
            ATT_MS_EXCH_XMIT_TIMEOUT_NON_URGENT = 131156,

            [Description("xMITTimeoutNormal")]
            ATT_MS_EXCH_XMIT_TIMEOUT_NORMAL = 131139,

            [Description("xMITTimeoutUrgent")]
            ATT_MS_EXCH_XMIT_TIMEOUT_URGENT = 131125,

            [Description("responsibleLocalDXA")]
            ATT_MS_EXCH_RESPONSIBLE_LOCAL_DXA = 131370,

            [Description("assocRemoteDXA")]
            ATT_MS_EXCH_ASSOC_REMOTE_DXA = 131371,

            [Description("supportingStack")]
            ATT_MS_EXCH_SUPPORTING_STACK = 131100,

            [Description("supportingStackBL")]
            ATT_MS_EXCH_SUPPORTING_STACK_BL = 131429,

            [Description("msExchHomeRoutingGroupDNBL")]
            ATT_MS_EXCH_HOME_ROUTING_GROUP_DN_BL = 1736716513,

            [Description("msExchSourceBridgeheadServersDN")]
            ATT_MS_EXCH_SOURCE_BRIDGEHEAD_SERVERS_DN = 1736716511,

            [Description("msExchBridgeheadedLocalConnectorsDNBL")]
            ATT_MS_EXCH_BRIDGEHEADED_LOCAL_CONNECTORS_DN_BL = 1736716515,

            [Description("msExchTargetBridgeheadServersDN")]
            ATT_MS_EXCH_TARGET_BRIDGEHEAD_SERVERS_DN = 1736716514,

            [Description("msExchBridgeheadedRemoteConnectorsDNBL")]
            ATT_MS_EXCH_BRIDGEHEADED_REMOTE_CONNECTORS_DN_BL = 1736716516,

            [Description("msExchOwningPFTree")]
            ATT_MS_EXCH_OWNING_PF_TREE = 1736715031,

            [Description("msExchOwningPFTreeBL")]
            ATT_MS_EXCH_OWNING_PF_TREE_BL = 1736715032,

            [Description("msExchPolicyList")]
            ATT_MS_EXCH_POLICY_LIST = 1030521684,

            [Description("msExchPolicyListBL")]
            ATT_MS_EXCH_POLICY_LIST_BL = 1030521685,

            [Description("msExchUseOABBL")]
            ATT_MS_EXCH_USE_OAB_BL = 1736704070,

            [Description("msExchAddressListServiceLink")]
            ATT_MS_EXCH_ADDRESS_LIST_SERVICE_LINK = 1736704075,

            [Description("msExchAddressListServiceBL")]
            ATT_MS_EXCH_ADDRESS_LIST_SERVICE_BL = 1736704074,

            [Description("msExchComputerLink")]
            ATT_MS_EXCH_COMPUTER_LINK = 1736704072,

            [Description("msExchExchangeServerLink")]
            ATT_MS_EXCH_EXCHANGE_SERVER_LINK = 1736704071,

            [Description("msExchConferenceZone")]
            ATT_MS_EXCH_CONFERENCE_ZONE = 1736713015,

            [Description("msExchConferenceZoneBL")]
            ATT_MS_EXCH_CONFERENCE_ZONE_BL = 1736713024,

            [Description("msExchESEParamStartFlushThreshold")]
            ATT_MS_EXCH_ESE_PARAM_START_FLUSH_THRESHOLD = 1736715056,

            [Description("msExchESEParamStopFlushThreshold")]
            ATT_MS_EXCH_ESE_PARAM_STOP_FLUSH_THRESHOLD = 1736715057,

            [Description("msExchIsConfigCA")]
            ATT_MS_EXCH_IS_CONFIG_CA = 1736704079,

            [Description("msExchPolicyLastAppliedTime")]
            ATT_MS_EXCH_POLICY_LAST_APPLIED_TIME = 1030521703,

            [Description("publicDelegates")]
            ATT_MS_EXCH_PUBLIC_DELEGATES = 131310,

            [Description("versionNumber")]
            ATT_VERSION_NUMBER = 589965,

            [Description("msExchAdminGroupsEnabled")]
            ATT_MS_EXCH_ADMIN_GROUPS_ENABLED = 1030521706,

            [Description("msExchAgingKeepTime")]
            ATT_MS_EXCH_AGING_KEEP_TIME = 1736715059,

            [Description("msExchAlternateServer")]
            ATT_MS_EXCH_ALTERNATE_SERVER = 1736716532,

            [Description("msExchAssociatedAG")]
            ATT_MS_EXCH_ASSOCIATED_AG = 1030521711,

            [Description("msExchccMailConnectAsPassword")]
            ATT_MS_EXCH_CCMAIL_CONNECT_AS_PASSWORD = 1736705207,

            [Description("msExchccMailConnectAsUserid")]
            ATT_MS_EXCH_CCMAIL_CONNECT_AS_USERID = 1736705206,

            [Description("msExchccMailPassword")]
            ATT_MS_EXCH_CCMAIL_PASSWORD = 1736705039,

            [Description("msExchChatClassRestrictions")]
            ATT_MS_EXCH_CHAT_CLASS_RESTRICTIONS = 1736712046,

            [Description("msExchChatClassScopeType")]
            ATT_MS_EXCH_CHAT_CLASS_SCOPE_TYPE = 1736712047,

            [Description("msExchChatExtensions")]
            ATT_MS_EXCH_CHAT_EXTENSIONS = 1736712048,

            [Description("msExchCIAvailable")]
            ATT_MS_EXCH_CI_AVAILABLE = 1736715066,

            [Description("msExchCILocation")]
            ATT_MS_EXCH_CI_LOCATION = 1736715068,

            [Description("msExchCIRebuildSchedule")]
            ATT_MS_EXCH_CI_REBUILD_SCHEDULE = 1736715063,

            [Description("msExchCIRebuildStyle")]
            ATT_MS_EXCH_CI_REBUILD_STYLE = 1736715065,

            [Description("msExchCIUpdateSchedule")]
            ATT_MS_EXCH_CI_UPDATE_SCHEDULE = 1736715062,

            [Description("msExchCIUpdateStyle")]
            ATT_MS_EXCH_CI_UPDATE_STYLE = 1736715064,

            [Description("msExchDataPath")]
            ATT_MS_EXCH_DATA_PATH = 1030521732,

            [Description("msExchDiscussionFolder")]
            ATT_MS_EXCH_DISCUSSION_FOLDER = 1736718002,

            [Description("msExchDS2MBOptions")]
            ATT_MS_EXCH_DS2MB_OPTIONS = 1736718001,

            [Description("msExchEncodeSMTPRelay")]
            ATT_MS_EXCH_ENCODE_SMTP_RELAY = 1736709053,

            [Description("msExchESEParamAssertAction")]
            ATT_MS_EXCH_ESE_PARAM_ASSERT_ACTION = 1736715074,

            [Description("msExchESEParamBaseName")]
            ATT_MS_EXCH_ESE_PARAM_BASE_NAME = 1736715076,

            [Description("msExchESEParamCacheSizeMin")]
            ATT_MS_EXCH_ESE_PARAM_CACHE_SIZE_MIN = 1736715075,

            [Description("msExchESEParamCheckpointDepthMax")]
            ATT_MS_EXCH_ESE_PARAM_CHECKPOINT_DEPTH_MAX = 1736715081,

            [Description("msExchESEParamCommitDefault")]
            ATT_MS_EXCH_ESE_PARAM_COMMIT_DEFAULT = 1736715077,

            [Description("msExchESEParamDbExtensionSize")]
            ATT_MS_EXCH_ESE_PARAM_DB_EXTENSION_SIZE = 1736715078,

            [Description("msExchESEParamEnableIndexChecking")]
            ATT_MS_EXCH_ESE_PARAM_ENABLE_INDEX_CHECKING = 1736715073,

            [Description("msExchESEParamEnableOnlineDefrag")]
            ATT_MS_EXCH_ESE_PARAM_ENABLE_ONLINE_DEFRAG = 1736715072,

            [Description("msExchESEParamEnableSortedRetrieveColumns")]
            ATT_MS_EXCH_ESE_PARAM_ENABLE_SORTED_RETRIEVE_COLUMNS = 1736715069,

            [Description("msExchESEParamGlobalMinVerPages")]
            ATT_MS_EXCH_ESE_PARAM_GLOBAL_MIN_VER_PAGES = 1736715082,

            [Description("msExchESEParamMaxCursors")]
            ATT_MS_EXCH_ESE_PARAM_MAX_CURSORS = 1736715071,

            [Description("msExchESEParamMaxTemporaryTables")]
            ATT_MS_EXCH_ESE_PARAM_MAX_TEMPORARY_TABLES = 1736715070,

            [Description("msExchESEParamPageFragment")]
            ATT_MS_EXCH_ESE_PARAM_PAGE_FRAGMENT = 1736715080,

            [Description("msExchESEParamPageTempDBMin")]
            ATT_MS_EXCH_ESE_PARAM_PAGE_TEMP_DB_MIN = 1736715079,

            [Description("msExchGWiseAPIGatewayPath")]
            ATT_MS_EXCH_GWISE_API_GATEWAY_PATH = 1736705201,

            [Description("msExchGWiseFilterType")]
            ATT_MS_EXCH_GWISE_FILTER_TYPE = 1736705205,

            [Description("msExchGWiseForeignDomain")]
            ATT_MS_EXCH_GWISE_FOREIGN_DOMAIN = 1736705204,

            [Description("msExchGWisePassword")]
            ATT_MS_EXCH_GWISE_PASSWORD = 1736705203,

            [Description("msExchGWiseUserId")]
            ATT_MS_EXCH_GWISE_USER_ID = 1736705202,

            [Description("msExchIMFirewallType")]
            ATT_MS_EXCH_IM_FIREWALL_TYPE = 1736711028,

            [Description("msExchIMHostName")]
            ATT_MS_EXCH_IM_HOST_NAME = 1736711034,

            [Description("msExchIMIPRange")]
            ATT_MS_EXCH_IM_IP_RANGE = 1736711030,

            [Description("msExchIMProxy")]
            ATT_MS_EXCH_IM_PROXY = 1736711029,

            [Description("inboundSites")]
            ATT_MS_EXCH_INBOUND_SITES = 131143,

            [Description("msExchInstalledComponents")]
            ATT_MS_EXCH_INSTALLED_COMPONENTS = 1030521704,

            [Description("msExchLegacyAccount")]
            ATT_MS_EXCH_LEGACY_ACCOUNT = 1030521720,

            [Description("msExchLegacyDomain")]
            ATT_MS_EXCH_LEGACY_DOMAIN = 1030521721,

            [Description("msExchLegacyPW")]
            ATT_MS_EXCH_LEGACY_PW = 1030521722,

            [Description("localBridgeHead")]
            ATT_MS_EXCH_LOCAL_BRIDGE_HEAD = 131383,

            [Description("localBridgeHeadAddress")]
            ATT_MS_EXCH_LOCAL_BRIDGE_HEAD_ADDRESS = 131297,

            [Description("msExchLocalDomains")]
            ATT_MS_EXCH_LOCAL_DOMAINS = 1030521712,

            [Description("msExchMailboxRetentionPeriod")]
            ATT_MS_EXCH_MAILBOX_RETENTION_PERIOD = 1736715060,

            [Description("msExchMaintenanceSchedule")]
            ATT_MS_EXCH_MAINTENANCE_SCHEDULE = 1736705029,

            [Description("msExchMaintenanceStyle")]
            ATT_MS_EXCH_MAINTENANCE_STYLE = 1736705030,

            [Description("msExchMandatoryAttributes")]
            ATT_MS_EXCH_MANDATORY_ATTRIBUTES = 1030521709,

            [Description("msExchMaxCachedViews")]
            ATT_MS_EXCH_MAX_CACHED_VIEWS = 1736715083,

            [Description("msExchMaxExtensionTime")]
            ATT_MS_EXCH_MAX_EXTENSION_TIME = 1736713028,

            [Description("msExchMaxParticipants")]
            ATT_MS_EXCH_MAX_PARTICIPANTS = 1736713027,

            [Description("msExchMonitoringDiskSpace")]
            ATT_MS_EXCH_MONITORING_DISK_SPACE = 1030521726,

            [Description("msExchMonitoringMonitoredServices")]
            ATT_MS_EXCH_MONITORING_MONITORED_SERVICES = 1030521725,

            [Description("msExchMonitoringQueuePollingFrequency")]
            ATT_MS_EXCH_MONITORING_QUEUE_POLLING_FREQUENCY = 1030521718,

            [Description("msExchMonitoringQueuePollingInterval")]
            ATT_MS_EXCH_MONITORING_QUEUE_POLLING_INTERVAL = 1030521717,

            [Description("msExchMonitoringResponses")]
            ATT_MS_EXCH_MONITORING_RESPONSES = 1030521727,

            [Description("msExchMTADatabasePath")]
            ATT_MS_EXCH_MTA_DATABASE_PATH = 752256593,

            [Description("msExchNoPFConnection")]
            ATT_MS_EXCH_NO_PF_CONNECTION = 1736715067,

            [Description("msExchNonMIMECharacterSet")]
            ATT_MS_EXCH_NON_MIME_CHARACTER_SET = 1030521723,

            [Description("msExchNotesPassword")]
            ATT_MS_EXCH_NOTES_PASSWORD = 1736705010,

            [Description("outboundSites")]
            ATT_MS_EXCH_OUTBOUND_SITES = 131072,

            [Description("msExchPolicyOrder")]
            ATT_MS_EXCH_POLICY_ORDER = 1030521707,

            [Description("msExchPolicyRoots")]
            ATT_MS_EXCH_POLICY_ROOTS = 1030521708,

            [Description("msExchPrevExportDLs")]
            ATT_MS_EXCH_PREV_EXPORT_DLS = 1736705002,

            [Description("remoteBridgeHead")]
            ATT_MS_EXCH_REMOTE_BRIDGE_HEAD = 131263,

            [Description("remoteBridgeHeadAddress")]
            ATT_MS_EXCH_REMOTE_BRIDGE_HEAD_ADDRESS = 131166,

            [Description("remoteSite")]
            ATT_MS_EXCH_REMOTE_SITE = 131099,

            [Description("replicationMailMsgSize")]
            ATT_MS_EXCH_REPLICATION_MAIL_MSG_SIZE = 131175,

            [Description("replicationStagger")]
            ATT_MS_EXCH_REPLICATION_STAGGER = 131421,

            [Description("msExchResolveP2")]
            ATT_MS_EXCH_RESOLVE_P2 = 1736716538,

            [Description("msExchRoutingETRNDomains")]
            ATT_MS_EXCH_ROUTING_ETRN_DOMAINS = 1736716530,

            [Description("msExchSchedPlusAGOnly")]
            ATT_MS_EXCH_SCHED_PLUS_AG_ONLY = 1736705191,

            [Description("msExchSchedPlusFullUpdate")]
            ATT_MS_EXCH_SCHED_PLUS_FULL_UPDATE = 1736705190,

            [Description("msExchSchedPlusSchedist")]
            ATT_MS_EXCH_SCHED_PLUS_SCHEDIST = 1736705192,

            [Description("msExchSecurityPassword")]
            ATT_MS_EXCH_SECURITY_PASSWORD = 1736709052,

            [Description("msExchServerBindingsTurflist")]
            ATT_MS_EXCH_SERVER_BINDINGS_TURFLIST = 1736716533,

            [Description("msExchSmtpEnableEXPN")]
            ATT_MS_EXCH_SMTP_ENABLE_EXPN = 1736716537,

            [Description("msExchSmtpEnableVRFY")]
            ATT_MS_EXCH_SMTP_ENABLE_VRFY = 1736716536,

            [Description("msExchSmtpTRNSmartHost")]
            ATT_MS_EXCH_SMTP_TRN_SMART_HOST = 1736716531,

            [Description("trustLevel")]
            ATT_MS_EXCH_TRUST_LEVEL = 131142,

            [Description("msExchTurfListAction")]
            ATT_MS_EXCH_TURF_LIST_ACTION = 1736716535,

            [Description("msExchTurfListNames")]
            ATT_MS_EXCH_TURF_LIST_NAMES = 1736716534,

            [Description("msExchVPIMConvertInbound")]
            ATT_MS_EXCH_VPIM_CONVERT_INBOUND = 752255600,

            [Description("msExchVPIMConvertOutbound")]
            ATT_MS_EXCH_VPIM_CONVERT_OUTBOUND = 752255601,

            [Description("msExchProxyGenOptions")]
            ATT_MSEXCH_PROXY_GEN_OPTIONS = 1030521724,

            [Description("msExchMasterService")]
            ATT_MS_EXCH_MASTER_SERVICE = 1736704082,

            [Description("msExchMasterServiceBL")]
            ATT_MS_EXCH_MASTER_SERVICE_BL = 1736704083,

            [Description("msExchExportContainersLinked")]
            ATT_MS_EXCH_EXPORT_CONTAINERS_LINKED = 1736705026,

            [Description("msExchExportContainersBL")]
            ATT_MS_EXCH_EXPORT_CONTAINERS_BL = 1736705027,

            [Description("msExchResponsibleMTAServer")]
            ATT_MS_EXCH_RESPONSIBLE_MTA_SERVER = 1030521713,

            [Description("msExchResponsibleMTAServerBL")]
            ATT_MS_EXCH_RESPONSIBLE_MTA_SERVER_BL = 1030521714,

            [Description("msExchImportContainerLinked")]
            ATT_MS_EXCH_IMPORT_CONTAINER_LINKED = 1736705028,

            [Description("purportedSearch")]
            ATT_PURPORTED_SEARCH = 590710,

            [Description("msExchAdmins")]
            ATT_MS_EXCH_ADMINS = 1030521744,

            [Description("msExchAllowEnhancedSecurity")]
            ATT_MS_EXCH_ALLOW_ENHANCED_SECURITY = 1736715087,

            [Description("msExchDatabaseBeingRestored")]
            ATT_MS_EXCH_DATABASE_BEING_RESTORED = 1736715085,

            [Description("msExchDatabaseCreated")]
            ATT_MS_EXCH_DATABASE_CREATED = 1736715084,

            [Description("msExchEnableInternalEvaluator")]
            ATT_MS_EXCH_ENABLE_INTERNAL_EVALUATOR = 1736704099,

            [Description("msExchEncryptedPassword")]
            ATT_MS_EXCH_ENCRYPTED_PASSWORD = 1030521742,

            [Description("msExchEncryptedPassword2")]
            ATT_MS_EXCH_ENCRYPTED_PASSWORD_2 = 1030521745,

            [Description("msExchLogonACL")]
            ATT_MS_EXCH_LOGON_ACL = 1736709057,

            [Description("msExchMailboxManagerActivationSchedule")]
            ATT_MS_EXCH_MAILBOX_MANAGER_ACTIVATION_SCHEDULE = 1030521747,

            [Description("msExchMailboxManagerActivationStyle")]
            ATT_MS_EXCH_MAILBOX_MANAGER_ACTIVATION_STYLE = 1030521748,

            [Description("msExchMailboxManagerAdminMode")]
            ATT_MS_EXCH_MAILBOX_MANAGER_ADMIN_MODE = 1030521757,

            [Description("msExchMailboxManagerAgeLimit")]
            ATT_MS_EXCH_MAILBOX_MANAGER_AGE_LIMIT = 1030521761,

            [Description("msExchMailboxManagerCustomMessage")]
            ATT_MS_EXCH_MAILBOX_MANAGER_CUSTOM_MESSAGE = 1030521750,

            [Description("msExchMailboxManagerFolderSettings")]
            ATT_MS_EXCH_MAILBOX_MANAGER_FOLDER_SETTINGS = 1030521758,

            [Description("msExchMailboxManagerKeepMessageClasses")]
            ATT_MS_EXCH_MAILBOX_MANAGER_KEEP_MESSAGE_CLASSES = 1030521754,

            [Description("msExchMailboxManagerMode")]
            ATT_MS_EXCH_MAILBOX_MANAGER_MODE = 1030521755,

            [Description("msExchMailboxManagerReportRecipient")]
            ATT_MS_EXCH_MAILBOX_MANAGER_REPORT_RECIPIENT = 1030521756,

            [Description("msExchMailboxManagerSendUserNotificationMail")]
            ATT_MS_EXCH_MAILBOX_MANAGER_SEND_USER_NOTIFICATION_MAIL = 1030521749,

            [Description("msExchMailboxManagerSizeLimit")]
            ATT_MS_EXCH_MAILBOX_MANAGER_SIZE_LIMIT = 1030521760,

            [Description("msExchMailboxManagerSizeLimitEnabled")]
            ATT_MS_EXCH_MAILBOX_MANAGER_SIZE_LIMIT_ENABLED = 1030521759,

            [Description("msExchMailboxManagerUserMessageBody")]
            ATT_MS_EXCH_MAILBOX_MANAGER_USER_MESSAGE_BODY = 1030521752,

            [Description("msExchMailboxManagerUserMessageFooter")]
            ATT_MS_EXCH_MAILBOX_MANAGER_USER_MESSAGE_FOOTER = 1030521753,

            [Description("msExchMailboxManagerUserMessageHeader")]
            ATT_MS_EXCH_MAILBOX_MANAGER_USER_MESSAGE_HEADER = 1030521751,

            [Description("msExchMessageJournalRecipient")]
            ATT_MS_EXCH_MESSAGE_JOURNAL_RECIPIENT = 1736709055,

            [Description("msExchMonitoringMode")]
            ATT_MS_EXCH_MONITORING_MODE = 1030521740,

            [Description("msExchMonitoringNotificationRate")]
            ATT_MS_EXCH_MONITORING_NOTIFICATION_RATE = 1030521737,

            [Description("msExchMonitoringPollingRate")]
            ATT_MS_EXCH_MONITORING_POLLING_RATE = 1030521738,

            [Description("msExchMonitoringResources")]
            ATT_MS_EXCH_MONITORING_RESOURCES = 1030521739,

            [Description("msExchNonAuthoritativeDomains")]
            ATT_MS_EXCH_NON_AUTHORITATIVE_DOMAINS = 1030521764,

            [Description("msExchPatchMDB")]
            ATT_MS_EXCH_PATCH_MDB = 1736715086,

            [Description("msExchProcessedSids")]
            ATT_MS_EXCH_PROCESSED_SIDS = 1736704089,

            [Description("msExchSearchBase")]
            ATT_MS_EXCH_SEARCH_BASE = 1736704091,

            [Description("msExchSearchScope")]
            ATT_MS_EXCH_SEARCH_SCOPE = 1736704092,

            [Description("msExchServerGlobalGroups")]
            ATT_MS_EXCH_SERVER_GLOBAL_GROUPS = 1030521763,

            [Description("msExchServerGroups")]
            ATT_MS_EXCH_SERVER_GROUPS = 1030521735,

            [Description("msExchServerLocalGroups")]
            ATT_MS_EXCH_SERVER_LOCAL_GROUPS = 1030521762,

            [Description("msExchServerPublicKey")]
            ATT_MS_EXCH_SERVER_PUBLIC_KEY = 1030521743,

            [Description("msExchSmtpExternalDNSServers")]
            ATT_MS_EXCH_SMTP_EXTERNAL_DNS_SERVERS = 1736709056,

            [Description("msExchTurfListOptions")]
            ATT_MS_EXCH_TURF_LIST_OPTIONS = 1736709054,

            [Description("msExchAppliesToSmtpVS")]
            ATT_MS_EXCH_APPLIES_TO_SMTP_VS = 1736709058,

            [Description("msExchAppliesToSmtpVSBL")]
            ATT_MS_EXCH_APPLIES_TO_SMTP_VS_BL = 1736709059,

            [Description("msExchConferenceMailbox")]
            ATT_MS_EXCH_CONFERENCE_MAILBOX = 1736713029,

            [Description("msExchMCUHostsSites")]
            ATT_MS_EXCH_MCU_HOSTS_SITES = 1736713031,

            [Description("msExchMCUHostsSitesBL")]
            ATT_MS_EXCH_MCU_HOSTS_SITES_BL = 1736713032,

            [Description("mail")]
            ATT_E_MAIL_ADDRESSES = 1376259,

            [Description("msExchRoutingGroupMembersDN")]
            ATT_MS_EXCH_ROUTING_GROUP_MEMBERS_DN = 1736716506,

            [Description("msExchDisableUDGConversion")]
            ATT_MS_EXCH_DISABLE_UDG_CONVERSION = 1736715088,

            [Description("msExchDomainGlobalGroupGuid")]
            ATT_MS_EXCH_DOMAIN_GLOBAL_GROUP_GUID = 1030521769,

            [Description("msExchDomainGlobalGroupSid")]
            ATT_MS_EXCH_DOMAIN_GLOBAL_GROUP_SID = 1030521771,

            [Description("msExchDomainLocalGroupGuid")]
            ATT_MS_EXCH_DOMAIN_LOCAL_GROUP_GUID = 1030521768,

            [Description("msExchDomainLocalGroupSid")]
            ATT_MS_EXCH_DOMAIN_LOCAL_GROUP_SID = 1030521770,

            [Description("msExchPfCreation")]
            ATT_MS_EXCH_PF_CREATION = 1736704100,

            [Description("msExchHomeRoutingGroup")]
            ATT_MS_EXCH_HOME_ROUTING_GROUP = 1736716539,

            [Description("msExchRoutingGroupMembersBL")]
            ATT_MS_EXCH_ROUTING_GROUP_MEMBERS_BL = 1736716540,

            [Description("msExchSecureBindings")]
            ATT_MS_EXCH_SECURE_BINDINGS = 1736706002,

            [Description("msExchServerBindings")]
            ATT_MS_EXCH_SERVER_BINDINGS = 1736706001,

            [Description("textEncodedORAddress")]
            ATT_TEXT_ENCODED_OR_ADDRESS = 1376258,

            [Description("mSMQUserSid")]
            ATT_MSMQ_USER_SID = 591161,

            [Description("netbootSCPBL")]
            ATT_NETBOOT_SCP_BL = 590688,

            [Description("msPKI-RA-Policies")]
            ATT_MS_PKI_RA_POLICIES = 591262,

            [Description("msPKI-RA-Signature")]
            ATT_MS_PKI_RA_SIGNATURE = 591253,

            [Description("msPKI-Enrollment-Flag")]
            ATT_MS_PKI_ENROLLMENT_FLAG = 591254,

            [Description("msPKI-Private-Key-Flag")]
            ATT_MS_PKI_PRIVATE_KEY_FLAG = 591255,

            [Description("msPKI-Minimal-Key-Size")]
            ATT_MS_PKI_MINIMAL_KEY_SIZE = 591257,

            [Description("msPKI-Certificate-Policy")]
            ATT_MS_PKI_CERTIFICATE_POLICY = 591263,

            [Description("msPKI-Supersede-Templates")]
            ATT_MS_PKI_SUPERSEDE_TEMPLATES = 591261,

            [Description("msPKI-Certificate-Name-Flag")]
            ATT_MS_PKI_CERTIFICATE_NAME_FLAG = 591256,

            [Description("msPKI-Template-Schema-Version")]
            ATT_MS_PKI_TEMPLATE_SCHEMA_VERSION = 591258,

            [Description("msPKI-Template-Minor-Revision")]
            ATT_MS_PKI_TEMPLATE_MINOR_REVISION = 591259,

            [Description("msDs-Schema-Extensions")]
            ATT_MS_DS_SCHEMA_EXTENSIONS = 591264,

            [Description("entryTTL")]
            ATT_ENTRY_TTL = 1769475,

            [Description("msWMI-ID")]
            ATT_MS_WMI_ID = 591451,

            [Description("msWMI-Mof")]
            ATT_MS_WMI_MOF = 591462,

            [Description("msWMI-Name")]
            ATT_MS_WMI_NAME = 591463,

            [Description("msWMI-Query")]
            ATT_MS_WMI_QUERY = 591466,

            [Description("msWMI-IntMin")]
            ATT_MS_WMI_INTMIN = 591454,

            [Description("msWMI-IntMax")]
            ATT_MS_WMI_INTMAX = 591453,

            [Description("msWMI-Author")]
            ATT_MS_WMI_AUTHOR = 591447,

            [Description("msWMI-Int8Min")]
            ATT_MS_WMI_INT8MIN = 591458,

            [Description("msWMI-Int8Max")]
            ATT_MS_WMI_INT8MAX = 591457,

            [Description("msCOM-ObjectId")]
            ATT_MS_COM_OBJECTID = 591252,

            [Description("msCOM-UserPartitionSetLink")]
            ATT_MS_COM_USERPARTITIONSETLINK = 591250,

            [Description("msCOM-UserLink")]
            ATT_MS_COM_USERLINK = 591249,

            [Description("msWMI-ChangeDate")]
            ATT_MS_WMI_CHANGEDATE = 591448,

            [Description("msWMI-IntDefault")]
            ATT_MS_WMI_INTDEFAULT = 591452,

            [Description("msWMI-TargetPath")]
            ATT_MS_WMI_TARGETPATH = 591472,

            [Description("msWMI-TargetType")]
            ATT_MS_WMI_TARGETTYPE = 591473,

            [Description("msWMI-Int8Default")]
            ATT_MS_WMI_INT8DEFAULT = 591456,

            [Description("msWMI-TargetClass")]
            ATT_MS_WMI_TARGETCLASS = 591469,

            [Description("msWMI-CreationDate")]
            ATT_MS_WMI_CREATIONDATE = 591450,

            [Description("msWMI-TargetObject")]
            ATT_MS_WMI_TARGETOBJECT = 591471,

            [Description("msWMI-PropertyName")]
            ATT_MS_WMI_PROPERTYNAME = 591465,

            [Description("msCOM-PartitionLink")]
            ATT_MS_COM_PARTITIONLINK = 591247,

            [Description("msWMI-QueryLanguage")]
            ATT_MS_WMI_QUERYLANGUAGE = 591467,

            [Description("msWMI-StringDefault")]
            ATT_MS_WMI_STRINGDEFAULT = 591460,

            [Description("msWMI-IntValidValues")]
            ATT_MS_WMI_INTVALIDVALUES = 591455,

            [Description("msWMI-Int8ValidValues")]
            ATT_MS_WMI_INT8VALIDVALUES = 591459,

            [Description("msWMI-TargetNameSpace")]
            ATT_MS_WMI_TARGETNAMESPACE = 591470,

            [Description("msWMI-ClassDefinition")]
            ATT_MS_WMI_CLASSDEFINITION = 591449,

            [Description("msWMI-NormalizedClass")]
            ATT_MS_WMI_NORMALIZEDCLASS = 591464,

            [Description("msCOM-PartitionSetLink")]
            ATT_MS_COM_PARTITIONSETLINK = 591248,

            [Description("msWMI-StringValidValues")]
            ATT_MS_WMI_STRINGVALIDVALUES = 591461,

            [Description("msWMI-SourceOrganization")]
            ATT_MS_WMI_SOURCEORGANIZATION = 591468,

            [Description("msCOM-DefaultPartitionLink")]
            ATT_MS_COM_DEFAULTPARTITIONLINK = 591251,

            [Description("msWMI-Parm1")]
            ATT_MS_WMI_PARM1 = 591506,

            [Description("msWMI-Parm2")]
            ATT_MS_WMI_PARM2 = 591507,

            [Description("msWMI-Parm3")]
            ATT_MS_WMI_PARM3 = 591508,

            [Description("msWMI-Parm4")]
            ATT_MS_WMI_PARM4 = 591509,

            [Description("msWMI-Class")]
            ATT_MS_WMI_CLASS = 591500,

            [Description("msWMI-Genus")]
            ATT_MS_WMI_GENUS = 591501,

            [Description("gPCWQLFilter")]
            ATT_GPC_WQL_FILTER = 591518,

            [Description("extraColumns")]
            ATT_EXTRA_COLUMNS = 591511,

            [Description("msWMI-intFlags1")]
            ATT_MS_WMI_INTFLAGS1 = 591502,

            [Description("msWMI-intFlags2")]
            ATT_MS_WMI_INTFLAGS2 = 591503,

            [Description("msWMI-intFlags3")]
            ATT_MS_WMI_INTFLAGS3 = 591504,

            [Description("msWMI-intFlags4")]
            ATT_MS_WMI_INTFLAGS4 = 591505,

            [Description("msWMI-ScopeGuid")]
            ATT_MS_WMI_SCOPEGUID = 591510,

            [Description("msFRS-Hub-Member")]
            ATT_MS_FRS_HUB_MEMBER = 591517,

            [Description("msPKI-OID-Attribute")]
            ATT_MS_PKI_OID_ATTRIBUTE = 591495,

            [Description("msFRS-Topology-Pref")]
            ATT_MS_FRS_TOPOLOGY_PREF = 591516,

            [Description("msPKI-RA-Application-Policies")]
            ATT_MS_PKI_RA_APPLICATION_POLICIES = 591499,

            [Description("adminMultiselectPropertyPages")]
            ATT_ADMIN_MULTISELECT_PROPERTY_PAGES = 591514,

            [Description("msDS-Security-Group-Extra-Classes")]
            ATT_MS_DS_SECURITY_GROUP_EXTRA_CLASSES = 591512,

            [Description("msPKI-Certificate-Application-Policy")]
            ATT_MS_PKI_CERTIFICATE_APPLICATION_POLICY = 591498,

            [Description("msDS-Non-Security-Group-Extra-Classes")]
            ATT_MS_DS_NON_SECURITY_GROUP_EXTRA_CLASSES = 591513,

            [Description("msMQ-Recipient-FormatName")]
            ATT_MSMQ_RECIPIENT_FORMATNAME = 591519,

            [Description("msTAPI-IpAddress")]
            ATT_MS_TAPI_IP_ADDRESS = 591525,

            [Description("msTAPI-ProtocolId")]
            ATT_MS_TAPI_PROTOCOL_ID = 591523,

            [Description("msTAPI-ConferenceBlob")]
            ATT_MS_TAPI_CONFERENCE_BLOB = 591524,

            [Description("ownerBL")]
            ATT_MS_EXCH_OWNER_BL = 131176,

            [Description("msTAPI-uid")]
            ATT_MS_TAPI_UNIQUE_IDENTIFIER = 591522,

            [Description("msDS-FilterContainers")]
            ATT_MS_DS_FILTER_CONTAINERS = 591527,

            [Description("msPKI-OIDLocalizedName")]
            ATT_MS_PKI_OID_LOCALIZEDNAME = 591536,

            [Description("uid")]
            ATT_UID = 1376257,

            [Description("audio")]
            ATT_AUDIO = 1376311,

            [Description("photo")]
            ATT_PHOTO = 1376263,

            [Description("jpegPhoto")]
            ATT_JPEGPHOTO = 1376316,

            [Description("secretary")]
            ATT_SECRETARY = 1376277,

            [Description("userPKCS12")]
            ATT_USERPKCS12 = 1442008,

            [Description("carLicense")]
            ATT_CARLICENSE = 1441793,

            [Description("roomNumber")]
            ATT_ROOMNUMBER = 1376262,

            [Description("uniqueMember")]
            ATT_UNIQUEMEMBER = 50,

            [Description("departmentNumber")]
            ATT_DEPARTMENTNUMBER = 1441794,

            [Description("unstructuredName")]
            ATT_UNSTRUCTUREDNAME = 1966082,

            [Description("preferredLanguage")]
            ATT_PREFERREDLANGUAGE = 1441831,

            [Description("x500uniqueIdentifier")]
            ATT_X500UNIQUEIDENTIFIER = 45,

            [Description("unstructuredAddress")]
            ATT_UNSTRUCTUREDADDRESS = 1966088,

            [Description("attributeCertificateAttribute")]
            ATT_ATTRIBUTECERTIFICATEATTRIBUTE = 58,

            [Description("serverRole")]
            ATT_SERVER_ROLE = 589981,

            [Description("hideFromAB")]
            ATT_HIDE_FROM_AB = 591604,

            [Description("msIIS-FTPRoot")]
            ATT_MS_IIS_FTP_ROOT = 591609,

            [Description("msIIS-FTPDir")]
            ATT_MS_IIS_FTP_DIR = 591610,

            [Description("dhcpServers")]
            ATT_DHCP_SERVERS = 590528,

            [Description("employeeNumber")]
            ATT_EMPLOYEE_NUMBER = 131682,

            [Description("employeeType")]
            ATT_EMPLOYEE_TYPE = 131685,

            [Description("msDS-NonMembersBL")]
            ATT_MS_DS_NON_MEMBERS_BL = 591618,

            [Description("msDS-AzClassId")]
            ATT_MS_DS_AZ_CLASS_ID = 591640,

            [Description("msDS-AzBizRule")]
            ATT_MS_DS_AZ_BIZ_RULE = 591625,

            [Description("msDS-AzScopeName")]
            ATT_MS_DS_AZ_SCOPE_NAME = 591623,

            [Description("msDS-AzOperationID")]
            ATT_MS_DS_AZ_OPERATION_ID = 591624,

            [Description("msDS-TasksForAzRole")]
            ATT_MS_DS_TASKS_FOR_AZ_ROLE = 591638,

            [Description("msDS-TasksForAzTask")]
            ATT_MS_DS_TASKS_FOR_AZ_TASK = 591634,

            [Description("msDS-AzDomainTimeout")]
            ATT_MS_DS_AZ_DOMAIN_TIMEOUT = 591619,

            [Description("msDS-AzScriptTimeout")]
            ATT_MS_DS_AZ_SCRIPT_TIMEOUT = 591621,

            [Description("msDS-AzGenerateAudits")]
            ATT_MS_DS_AZ_GENERATE_AUDITS = 591629,

            [Description("msDS-AzApplicationData")]
            ATT_MS_DS_AZ_APPLICATION_DATA = 591643,

            [Description("msDS-AzApplicationName")]
            ATT_MS_DS_AZ_APPLICATION_NAME = 591622,

            [Description("msDS-AzBizRuleLanguage")]
            ATT_MS_DS_AZ_BIZ_RULE_LANGUAGE = 591626,

            [Description("msDS-OperationsForAzRole")]
            ATT_MS_DS_OPERATIONS_FOR_AZ_ROLE = 591636,

            [Description("msDS-OperationsForAzTask")]
            ATT_MS_DS_OPERATIONS_FOR_AZ_TASK = 591632,

            [Description("msDS-AzApplicationVersion")]
            ATT_MS_DS_AZ_APPLICATION_VERSION = 591641,

            [Description("msDS-AzScriptEngineCacheMax")]
            ATT_MS_DS_AZ_SCRIPT_ENGINE_CACHE_MAX = 591620,

            [Description("msDS-AzTaskIsRoleDefinition")]
            ATT_MS_DS_AZ_TASK_IS_ROLE_DEFINITION = 591642,

            [Description("msDS-AzLastImportedBizRulePath")]
            ATT_MS_DS_AZ_LAST_IMPORTED_BIZ_RULE_PATH = 591627,

            [Description("msDS-TasksForAzRoleBL")]
            ATT_MS_DS_TASKS_FOR_AZ_ROLE_BL = 591639,

            [Description("msDS-TasksForAzTaskBL")]
            ATT_MS_DS_TASKS_FOR_AZ_TASK_BL = 591635,

            [Description("msDS-MembersForAzRoleBL")]
            ATT_MS_DS_MEMBERS_FOR_AZ_ROLE_BL = 591631,

            [Description("msDS-OperationsForAzRoleBL")]
            ATT_MS_DS_OPERATIONS_FOR_AZ_ROLE_BL = 591637,

            [Description("msDS-OperationsForAzTaskBL")]
            ATT_MS_DS_OPERATIONS_FOR_AZ_TASK_BL = 591633,

            [Description("msieee80211-ID")]
            ATT_MS_IEEE_80211_ID = 591647,

            [Description("msieee80211-Data")]
            ATT_MS_IEEE_80211_DATA = 591645,

            [Description("msieee80211-DataType")]
            ATT_MS_IEEE_80211_DATA_TYPE = 591646,

            [Description("msDS-AzMajorVersion")]
            ATT_MS_DS_AZ_MAJOR_VERSION = 591648,

            [Description("msDS-AzMinorVersion")]
            ATT_MS_DS_AZ_MINOR_VERSION = 591649,

            [Description("host")]
            ATT_HOST = 1376265,

            [Description("drink")]
            ATT_DRINK = 1376261,

            [Description("userClass")]
            ATT_USERCLASS = 1376264,

            [Description("msDS-Integer")]
            ATT_MS_DS_INTEGER = 591659,

            [Description("buildingName")]
            ATT_BUILDINGNAME = 1376304,

            [Description("msDS-DateTime")]
            ATT_MS_DS_DATE_TIME = 591656,

            [Description("documentTitle")]
            ATT_DOCUMENTTITLE = 1376268,

            [Description("msDS-ByteArray")]
            ATT_MS_DS_BYTE_ARRAY = 591655,

            [Description("associatedName")]
            ATT_ASSOCIATEDNAME = 1376294,

            [Description("documentAuthor")]
            ATT_DOCUMENTAUTHOR = 1376270,

            [Description("houseIdentifier")]
            ATT_HOUSEIDENTIFIER = 51,

            [Description("documentVersion")]
            ATT_DOCUMENTVERSION = 1376269,

            [Description("msDS-ExternalKey")]
            ATT_MS_DS_EXTERNAL_KEY = 591657,

            [Description("associatedDomain")]
            ATT_ASSOCIATEDDOMAIN = 1376293,

            [Description("documentLocation")]
            ATT_DOCUMENTLOCATION = 1376271,

            [Description("uniqueIdentifier")]
            ATT_UNIQUEIDENTIFIER = 1376300,

            [Description("documentPublisher")]
            ATT_DOCUMENTPUBLISHER = 1376312,

            [Description("msDS-ExternalStore")]
            ATT_MS_DS_EXTERNAL_STORE = 591658,

            [Description("documentIdentifier")]
            ATT_DOCUMENTIDENTIFIER = 1376267,

            [Description("msDS-ObjectReference")]
            ATT_MS_DS_OBJECT_REFERENCE = 591664,

            [Description("organizationalStatus")]
            ATT_ORGANIZATIONALSTATUS = 1376301,

            [Description("userCertificate")]
            ATT_X509_CERT = 36,

            [Description("certificateRevocationList")]
            ATT_CERTIFICATE_REVOCATION_LIST = 39,

            [Description("authorityRevocationList")]
            ATT_AUTHORITY_REVOCATION_LIST = 38,

            [Description("cRLPartitionedRevocationList")]
            ATT_CRL_PARTITIONED_REVOCATION_LIST = 590507,

            [Description("deltaRevocationList")]
            ATT_DELTA_REVOCATION_LIST = 53,

            [Description("crossCertificatePair")]
            ATT_CROSS_CERTIFICATE_PAIR = 40,

            [Description("msPKI-OID-CPS")]
            ATT_MS_PKI_OID_CPS = 591496,

            [Description("msPKI-OID-User-Notice")]
            ATT_MS_PKI_OID_USER_NOTICE = 591497,

            [Description("userSMIMECertificate")]
            ATT_USER_SMIME_CERTIFICATE = 1310860,

            [Description("msDS-Settings")]
            ATT_MS_DS_SETTINGS = 591521,

            [Description("pKT")]
            ATT_PKT = 590030,

            [Description("ipPhone")]
            ATT_PHONE_IP_PRIMARY = 590545,

            [Description("notes")]
            ATT_ADDITIONAL_INFORMATION = 590089,

            [Description("mSMQSignCertificates")]
            ATT_MSMQ_SIGN_CERTIFICATES = 590771,

            [Description("mSMQSignCertificatesMig")]
            ATT_MSMQ_SIGN_CERTIFICATES_MIG = 590791,

            [Description("msDS-ObjectReferenceBL")]
            ATT_MS_DS_OBJECT_REFERENCE_BL = 591665,

            [Description("msDs-MaxValues")]
            ATT_MS_DS_MAX_VALUES = 591666,

            [Description("DUP-labeledURI-6cfed1a7-c325-47fa-b774-463d525b05a6")]
            ATT_LABELEDURI = 1900601,

            [Description("gfiFEXVersion")]
            ATT_GFI_FEX_VERSION = 1603272704,

            [Description("gfiFEXFlags")]
            ATT_GFI_FEX_FLAGS = 1603272705,

            [Description("gfiFEXThreadsIn")]
            ATT_GFI_FEX_THREADSIN = 1603272706,

            [Description("gfiFEXThreadsOut")]
            ATT_GFI_FEX_THREADSOUT = 1603272707,

            [Description("gfiFEXSleepIn")]
            ATT_GFI_FEX_SLEEPIN = 1603272708,

            [Description("gfiFEXSleepOut")]
            ATT_GFI_FEX_SLEEPOUT = 1603272709,

            [Description("gfiFEXPollIn")]
            ATT_GFI_FEX_POLLIN = 1603272710,

            [Description("gfiFEXPollOut")]
            ATT_GFI_FEX_POLLOUT = 1603272711,

            [Description("gfiFEXInQueue")]
            ATT_GFI_FEX_INQUEUE = 1603272712,

            [Description("gfiFEXOutQueue")]
            ATT_GFI_FEX_OUTQUEUE = 1603272713,

            [Description("gfiFEXDataDir")]
            ATT_GFI_FEX_DATADIR = 1603272714,

            [Description("gfiFEXContacts")]
            ATT_GFI_FEX_CONTACTS = 1603272715,

            [Description("gfiFEXFMServer")]
            ATT_GFI_FEX_FMSERVER = 1603272716,

            [Description("gfiFEXLogs")]
            ATT_GFI_FEX_LOGS = 1603272717,

            [Description("mSSMSSiteCode")]
            ATT_MS_SMS_SITE_CODE = 1844510721,

            [Description("mSSMSAssignmentSiteCode")]
            ATT_MS_SMS_ASSIGNMENT_SITE_CODE = 1844510729,

            [Description("mSSMSSiteBoundaries")]
            ATT_MS_SMS_SITE_BOUNDARIES = 1844510722,

            [Description("mSSMSRoamingBoundaries")]
            ATT_MS_SMS_ROAMING_BOUNDARIES = 1844510723,

            [Description("mSSMSDefaultMP")]
            ATT_MS_SMS_DEFAULT_MP = 1844510724,

            [Description("mSSMSDeviceManagementPoint")]
            ATT_MS_SMS_DEVICE_MANAGEMENT_POINT = 1844510730,

            [Description("mSSMSMPName")]
            ATT_MS_SMS_MP_NAME = 1844510725,

            [Description("mSSMSMPAddress")]
            ATT_MS_SMS_MP_ADDRESS = 1844510726,

            [Description("mSSMSRangedIPLow")]
            ATT_MS_SMS_RANGED_IP_LOW = 1844510727,

            [Description("mSSMSRangedIPHigh")]
            ATT_MS_SMS_RANGED_IP_HIGH = 1844510728,

            [Description("msExchSchemaVersionAdc")]
            ATT_MS_EXCH_SCHEMA_VERSION_ADC = 1736704098,

            [Description("msExchCalConClientWait")]
            ATT_MS_EXCH_CALCON_CLIENT_WAIT = 1736705043,

            [Description("msExchCalConProviders")]
            ATT_MS_EXCH_CALCON_PROVIDERS = 1736705042,

            [Description("msExchCalConQueryWindow")]
            ATT_MS_EXCH_CALCON_QUERY_WINDOW = 1736705040,

            [Description("msExchCalConRefreshInterval")]
            ATT_MS_EXCH_CALCON_REFRESH_INTERVAL = 1736705041,

            [Description("msExchCalConTargetSiteDN")]
            ATT_MS_EXCH_CALCON_TARGET_SITEDN = 1736705044,

            [Description("msExchGWiseAPIGateway")]
            ATT_MS_EXCH_GWISE_API_GATEWAY = 1736705045,

            [Description("msExchHouseIdentifier")]
            ATT_MS_EXCH_HOUSE_IDENTIFIER = 131668,

            [Description("msExchAuthMailDisposition")]
            ATT_MS_EXCH_AUTHMAILDISPOSITION = 594885,

            [Description("msExchAuthorizationPersistence")]
            ATT_MS_EXCH_AUTHORIZATION_PERSISTENCE = 1736719011,

            [Description("msExchBarMessageClass")]
            ATT_MS_EXCH_BAR_MESSAGE_CLASS = 1736705064,

            [Description("msExchChatMaxConnectionsPerIP")]
            ATT_MS_EXCH_CHAT_MAX_CONNECTIONS_PER_IP = 1736712049,

            [Description("msExchChatMaxOctetsToMask")]
            ATT_MS_EXCH_CHAT_MAX_OCTETS_TO_MASK = 1736712050,

            [Description("msExchDefaultLoadFile")]
            ATT_MS_EXCH_DEFAULT_LOAD_FILE = 1736719010,

            [Description("msExchDynamicDLBaseDN")]
            ATT_MS_EXCH_DYNAMIC_DL_BASEDN = 1736716543,

            [Description("msExchDynamicDLFilter")]
            ATT_MS_EXCH_DYNAMIC_DL_FILTER = 1736716544,

            [Description("msExchEncryptedAnonymousPassword")]
            ATT_MS_EXCH_ENCRYPTED_ANONYMOUS_PASSWORD = 1736719009,

            [Description("msExchFolderAffinityCustom")]
            ATT_MS_EXCH_FOLDER_AFFINITY_CUSTOM = 1736715090,

            [Description("msExchFolderAffinityList")]
            ATT_MS_EXCH_FOLDER_AFFINITY_LIST = 1736715089,

            [Description("msExchMaxRestoreStorageGroups")]
            ATT_MS_EXCH_MAX_RESTORE_STORAGE_GROUPS = 1736715095,

            [Description("msExchOrigMDB")]
            ATT_MS_EXCH_ORIG_MDB = 1736715093,

            [Description("msExchOtherAuthenticationFlags")]
            ATT_MS_EXCH_OTHER_AUTHENTICATION_FLAGS = 1736706017,

            [Description("msExchPreferredBackfillSource")]
            ATT_MS_EXCH_PREFERRED_BACKFILL_SOURCE = 1736715094,

            [Description("msExchRecipTurfListNames")]
            ATT_MS_EXCH_RECIP_TURF_LIST_NAMES = 1736709070,

            [Description("msExchRecipTurfListOptions")]
            ATT_MS_EXCH_RECIP_TURF_LIST_OPTIONS = 1736709071,

            [Description("msExchSASLMechanisms")]
            ATT_MS_EXCH_SASL_MECHANISMS = 1736706018,

            [Description("msExchServerBindingsFiltering")]
            ATT_MS_EXCH_SERVER_BINDINGS_FILTERING = 1736709072,

            [Description("msExchSmtpConnectionRulesPriority")]
            ATT_MS_EXCH_SMTP_CONNECTION_RULES_PRIORITY = 1736709064,

            [Description("msExchSmtpConnectionTurfListDisplay")]
            ATT_MS_EXCH_SMTP_CONNECTION_TURF_LIST_DISPLAY = 1736709065,

            [Description("msExchSmtpConnectionTurfListDNS")]
            ATT_MS_EXCH_SMTP_CONNECTION_TURF_LIST_DNS = 1736709067,

            [Description("msExchSmtpConnectionTurfListMask")]
            ATT_MS_EXCH_SMTP_CONNECTION_TURF_LIST_MASK = 1736709069,

            [Description("msExchSmtpConnectionTurfListOptions")]
            ATT_MS_EXCH_SMTP_CONNECTION_TURF_LIST_OPTIONS = 1736709066,

            [Description("msExchSmtpConnectionTurfListResponse")]
            ATT_MS_EXCH_SMTP_CONNECTION_TURF_LIST_RESPONSE = 1736709068,

            [Description("msExchSmtpConnectionWhitelist")]
            ATT_MS_EXCH_SMTP_CONNECTION_WHITELIST = 1736709063,

            [Description("msExchSubmitRelaySD")]
            ATT_MS_EXCH_SUBMITRELAYSD = 594884,

            [Description("co")]
            ATT_TEXT_COUNTRY = 131203,

            [Description("msExchBackEndVDirURL")]
            ATT_MS_EXCH_BACKEND_VDIR_URL = 1736719012,

            [Description("msExchOmaCarrierAddress")]
            ATT_MS_EXCH_OMA_CARRIER_ADDRESS = 1102774411,

            [Description("msExchOmaCarrierType")]
            ATT_MS_EXCH_OMA_CARRIER_TYPE = 1102774417,

            [Description("msExchOmaCarrierUrl")]
            ATT_MS_EXCH_OMA_CARRIER_URL = 1102774418,

            [Description("msExchOmaConfiguration")]
            ATT_MS_EXCH_OMA_CONFIGURATION = 1102774409,

            [Description("msExchOmaDeliverer")]
            ATT_MS_EXCH_OMA_DELIVERER = 1102774416,

            [Description("msExchOmaDeliveryProviderDN")]
            ATT_MS_EXCH_OMA_DELIVERY_PROVIDER_DN = 1102774410,

            [Description("msExchOmaDeviceCapabilityDN")]
            ATT_MS_EXCH_OMA_DEVICE_CAPABILITY_DN = 1102774405,

            [Description("msExchOmaExtendedProperties")]
            ATT_MS_EXCH_OMA_EXTENDED_PROPERTIES = 1102774415,

            [Description("msExchOmaFormatter")]
            ATT_MS_EXCH_OMA_FORMATTER = 1102774407,

            [Description("msExchOmaTranslator")]
            ATT_MS_EXCH_OMA_TRANSLATOR = 1102774408,

            [Description("msExchOmaValidater")]
            ATT_MS_EXCH_OMA_VALIDATER = 1102774406,

            [Description("msExchRestore")]
            ATT_MS_EXCH_RESTORE = 1736715092,

            [Description("msExchAddressListOU")]
            ATT_MS_EXCH_ADDRESS_LIST_OU = 1736704112,

            [Description("msExchESEParamCachedClosedTables")]
            ATT_MS_EXCH_ESE_PARAM_CACHED_CLOSED_TABLES = 1736715096,

            [Description("msExchMinAdminVersion")]
            ATT_MS_EXCH_MIN_ADMIN_VERSION = 1030521773,

            [Description("msExchSMTPGlobalIPAcceptList")]
            ATT_MS_EXCH_SMTP_GLOBAL_IP_ACCEPT_LIST = 1736709073,

            [Description("msExchSMTPGlobalIPDenyList")]
            ATT_MS_EXCH_SMTP_GLOBAL_IP_DENY_LIST = 1736709074,

            [Description("msExchUceBlockThreshold")]
            ATT_MS_EXCH_UCE_BLOCK_THRESHOLD = 1736716601,

            [Description("msExchUceEnabled")]
            ATT_MS_EXCH_UCE_ENABLED = 1736716600,

            [Description("msExchUceStoreActionThreshold")]
            ATT_MS_EXCH_UCE_STORE_ACTION_THRESHOLD = 1736716602,

            [Description("msLimitLoginUsername")]
            ATT_MS_LIMITLOGINUSERNAME = 32178177,

            [Description("msLimitLoginQuota")]
            ATT_MS_LIMITLOGINQUOTA = 32178178,

            [Description("msLimitLoginDenyLoginOnQuotaExceed")]
            ATT_MS_LIMITLOGINDENYLOGINONQUOTAEXCEED = 32178179,

            [Description("msLimitLoginInfo")]
            ATT_MS_LIMITLOGININFO = 32178180,

            [Description("MSMQ-SecuredSource")]
            ATT_MSMQ_SECURED_SOURCE = 591537,

            [Description("MSMQ-MulticastAddress")]
            ATT_MSMQ_MULTICAST_ADDRESS = 591538,

            [Description("printMemory")]
            ATT_PRINT_MEMORY = 590106,

            [Description("printRate")]
            ATT_PRINT_RATE = 590109,

            [Description("printRateUnit")]
            ATT_PRINT_RATE_UNIT = 590110,

            [Description("msDRM-IdentityCertificate")]
            ATT_MS_DRM_IDENTITY_CERTIFICATE = 591667,

            [Description("msExchELCExpiryAgeLimit")]
            ATT_MS_EXCH_ELC_EXPIRY_AGE_LIMIT = 1030522039,

            [Description("msExchELCFolderQuota")]
            ATT_MS_EXCH_ELC_FOLDER_QUOTA = 1030522037,

            [Description("msExchELCMessageClass")]
            ATT_MS_EXCH_ELC_MESSAGE_CLASS = 782664883,

            [Description("msExchRecipientTemplateFlags")]
            ATT_MS_EXCH_RECIPIENT_TEMPLATE_FLAGS = 1030522033,

            [Description("msExchResourceCapacity")]
            ATT_MS_EXCH_RESOURCE_CAPACITY = 1030522012,

            [Description("msExchResourceDisplay")]
            ATT_MS_EXCH_RESOURCE_DISPLAY = 1030522014,

            [Description("msExchResourceLocationSchema")]
            ATT_MS_EXCH_RESOURCE_LOCATION_SCHEMA = 1030522010,

            [Description("msExchResourceMetaData")]
            ATT_MS_EXCH_RESOURCE_META_DATA = 1030522013,

            [Description("msExchUMAutoAttendantAfterHourFeatures")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_AFTER_HOUR_FEATURES = 1030522085,

            [Description("msExchUMAutoAttendantBusinessHourFeatures")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_BUSINESS_HOUR_FEATURES = 1030522084,

            [Description("msExchUMAutoAttendantBusinessHourSchedule")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_BUSINESS_HOUR_SCHEDULE = 1030522083,

            [Description("msExchUMAutoAttendantDialedNumbers")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_DIALED_NUMBERS = 1030522080,

            [Description("msExchUMAutoAttendantFlags")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_FLAGS = 1030522088,

            [Description("msExchUMAutoAttendantHolidaySchedule")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_HOLIDAY_SCHEDULE = 1030522087,

            [Description("msExchUMAutoAttendantTimeZone")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_TIME_ZONE = 1030522082,

            [Description("msExchUMCallFailuresToDisconnect")]
            ATT_MS_EXCH_UM_CALL_FAILURES_TO_DISCONNECT = 1030522054,

            [Description("msExchUMDialByNamePrimary")]
            ATT_MS_EXCH_UM_DIAL_BY_NAME_PRIMARY = 1030522056,

            [Description("msExchUMDialByNameSecondary")]
            ATT_MS_EXCH_UM_DIAL_BY_NAME_SECONDARY = 1030522057,

            [Description("msExchUMDtmfMap")]
            ATT_MS_EXCH_UM_DTMF_MAP = 1030522021,

            [Description("msExchUMEnabledFlags")]
            ATT_MS_EXCH_UM_ENABLED_FLAGS = 1030522015,

            [Description("msExchUMEnabledText")]
            ATT_MS_EXCH_UM_ENABLED_TEXT = 1030522044,

            [Description("msExchUMFaxEnabled")]
            ATT_MS_EXCH_UM_FAX_ENABLED = 1030522052,

            [Description("msExchUMFaxId")]
            ATT_MS_EXCH_UM_FAX_ID = 1030522042,

            [Description("msExchUMFaxMessageText")]
            ATT_MS_EXCH_UM_FAX_MESSAGE_TEXT = 1030522043,

            [Description("msExchUMHuntGroupNumber")]
            ATT_MS_EXCH_UM_HUNT_GROUP_NUMBER = 1030522073,

            [Description("msExchUMInputRetries")]
            ATT_MS_EXCH_UM_INPUT_RETRIES = 1030522067,

            [Description("msExchUMInputTimeout")]
            ATT_MS_EXCH_UM_INPUT_TIMEOUT = 1030522066,

            [Description("msExchUMIPGatewayAddress")]
            ATT_MS_EXCH_UM_IP_GATEWAY_ADDRESS = 1030522072,

            [Description("msExchUMListInDirectorySearch")]
            ATT_MS_EXCH_UM_LIST_IN_DIRECTORY_SEARCH = 1030522022,

            [Description("msExchUMLogonFailuresBeforeDisconnect")]
            ATT_MS_EXCH_UM_LOGON_FAILURES_BEFORE_DISCONNECT = 1030522090,

            [Description("msExchUMMaxCallDuration")]
            ATT_MS_EXCH_UM_MAX_CALL_DURATION = 1030522063,

            [Description("msExchUMMaxRecordingDuration")]
            ATT_MS_EXCH_UM_MAX_RECORDING_DURATION = 1030522064,

            [Description("msExchUMNumberingPlanDigits")]
            ATT_MS_EXCH_UM_NUMBERING_PLAN_DIGITS = 1030522049,

            [Description("msExchUMOperatorNumber")]
            ATT_MS_EXCH_UM_OPERATOR_NUMBER = 1030522023,

            [Description("msExchUMPinPolicyAccountLockoutFailures")]
            ATT_MS_EXCH_UM_PIN_POLICY_ACCOUNT_LOCKOUT_FAILURES = 1030522027,

            [Description("msExchUMPinPolicyDisallowCommonPatterns")]
            ATT_MS_EXCH_UM_PIN_POLICY_DISALLOW_COMMON_PATTERNS = 1030522028,

            [Description("msExchUMPinPolicyMinPasswordLength")]
            ATT_MS_EXCH_UM_PIN_POLICY_MIN_PASSWORD_LENGTH = 1030522025,

            [Description("msExchUMPinPolicyNumberOfPreviousPasswordsDisallowed")]
            ATT_MS_EXCH_UM_PIN_POLICY_NUMBER_OF_PREVIOUS_PASSWORDS_DISALLOWED = 1030522089,

            [Description("msExchUMRecordingIdleTimeout")]
            ATT_MS_EXCH_UM_RECORDING_IDLE_TIMEOUT = 1030522065,

            [Description("msExchUMResetPasswordValue")]
            ATT_MS_EXCH_UM_RESET_PASSWORD_VALUE = 1030522053,

            [Description("msExchUMResetPINText")]
            ATT_MS_EXCH_UM_RESET_PIN_TEXT = 1030522045,

            [Description("msExchUMSpokenName")]
            ATT_MS_EXCH_UM_SPOKEN_NAME = 1030522016,

            [Description("msExchUMTrunkAccessCode")]
            ATT_MS_EXCH_UM_TRUNK_ACCESS_CODE = 1030522055,

            [Description("msExchUMVoiceMailOriginator")]
            ATT_MS_EXCH_UM_VOICE_MAIL_ORIGINATOR = 1030522051,

            [Description("msExchUMVoiceMailPilotNumbers")]
            ATT_MS_EXCH_UM_VOICE_MAIL_PILOT_NUMBERS = 1030522050,

            [Description("msExchUMVoiceMailText")]
            ATT_MS_EXCH_UM_VOICE_MAIL_TEXT = 1030522046,

            [Description("msExchELCFolderLink")]
            ATT_MS_EXCH_ELC_FOLDER_LINK = 1030522029,

            [Description("msExchELCFolderBL")]
            ATT_MS_EXCH_ELC_FOLDER_BL = 1030522030,

            [Description("msExchMailboxTemplateLink")]
            ATT_MS_EXCH_MAILBOX_TEMPLATE_LINK = 1030522031,

            [Description("msExchMailboxTemplateBL")]
            ATT_MS_EXCH_MAILBOX_TEMPLATE_BL = 1030522032,

            [Description("msExchUMTemplateLink")]
            ATT_MS_EXCH_UM_TEMPLATE_LINK = 1030522047,

            [Description("msExchUMTemplateBL")]
            ATT_MS_EXCH_UM_TEMPLATE_BL = 1030522048,

            [Description("msExchUMRecipientDialPlanLink")]
            ATT_MS_EXCH_UM_RECIPIENT_DIAL_PLAN_LINK = 1030522068,

            [Description("msExchUMRecipientDialPlanBL")]
            ATT_MS_EXCH_UM_RECIPIENT_DIAL_PLAN_BL = 1030522069,

            [Description("msExchUMServerDialPlanLink")]
            ATT_MS_EXCH_UM_SERVER_DIAL_PLAN_LINK = 1030522070,

            [Description("msExchUMServerDialPlanBL")]
            ATT_MS_EXCH_UM_SERVER_DIAL_PLAN_BL = 1030522071,

            [Description("msExchUMIPGatewayDialPlanLink")]
            ATT_MS_EXCH_UM_IP_GATEWAY_DIAL_PLAN_LINK = 1030522074,

            [Description("msExchUMIPGatewayDialPlanBL")]
            ATT_MS_EXCH_UM_IP_GATEWAY_DIAL_PLAN_BL = 1030522075,

            [Description("msExchUMIPGatewayServerLink")]
            ATT_MS_EXCH_UM_IP_GATEWAY_SERVER_LINK = 1030522076,

            [Description("msExchUMIPGatewayServerBL")]
            ATT_MS_EXCH_UM_IP_GATEWAY_SERVER_BL = 1030522077,

            [Description("msExchUMAutoAttendantDialPlanLink")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_DIAL_PLAN_LINK = 1030522078,

            [Description("msExchUMAutoAttendantDialPlanBL")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_DIAL_PLAN_BL = 1030522079,

            [Description("localeID")]
            ATT_LOCALE_ID = 589882,

            [Description("msExchADCGlobalNames")]
            ATT_MS_EXCH_ADC_GLOBAL_NAMES = 1736704063,

            [Description("msExchALObjectVersion")]
            ATT_MS_EXCH_AL_OBJECT_VERSION = 1736704059,

            [Description("altRecipient")]
            ATT_MS_EXCH_ALT_RECIPIENT = 131198,

            [Description("altRecipientBL")]
            ATT_MS_EXCH_ALT_RECIPIENT_BL = 131366,

            [Description("attributeCertificate")]
            ATT_MS_EXCH_ATTRIBUTE_CERTIFICATE = 131659,

            [Description("authOrig")]
            ATT_MS_EXCH_AUTH_ORIG = 131201,

            [Description("authOrigBL")]
            ATT_MS_EXCH_AUTH_ORIG_BL = 131362,

            [Description("autoReply")]
            ATT_MS_EXCH_AUTOREPLY = 131358,

            [Description("autoReplyMessage")]
            ATT_MS_EXCH_AUTOREPLY_MESSAGE = 131359,

            [Description("msExchConferenceMailboxBL")]
            ATT_MS_EXCH_CONFERENCE_MAILBOX_BL = 1736713030,

            [Description("msExchControllingZone")]
            ATT_MS_EXCH_CONTROLLING_ZONE = 1736713026,

            [Description("msExchCustomProxyAddresses")]
            ATT_MS_EXCH_CUSTOM_PROXY_ADDRESSES = 1030521729,

            [Description("deletedItemFlags")]
            ATT_MS_EXCH_DELETED_ITEM_FLAGS = 131178,

            [Description("delivContLength")]
            ATT_MS_EXCH_DELIV_CONT_LENGTH = 131210,

            [Description("delivExtContTypes")]
            ATT_MS_EXCH_DELIV_EXT_CONT_TYPES = 131212,

            [Description("deliverAndRedirect")]
            ATT_MS_EXCH_DELIVER_AND_REDIRECT = 131262,

            [Description("deliveryMechanism")]
            ATT_MS_EXCH_DELIVERY_MECHANISM = 131313,

            [Description("dLMemDefault")]
            ATT_MS_EXCH_DL_MEM_DEFAULT = 1736716527,

            [Description("dLMemRejectPerms")]
            ATT_MS_EXCH_DL_MEM_REJECT_PERMS = 131119,

            [Description("dLMemRejectPermsBL")]
            ATT_MS_EXCH_DL_MEM_REJECT_PERMS_BL = 131365,

            [Description("dLMemSubmitPerms")]
            ATT_MS_EXCH_DL_MEM_SUBMIT_PERMS = 131216,

            [Description("dLMemSubmitPermsBL")]
            ATT_MS_EXCH_DL_MEM_SUBMIT_PERMS_BL = 131363,

            [Description("dLMemberRule")]
            ATT_MS_EXCH_DL_MEMBER_RULE = 131402,

            [Description("enabledProtocols")]
            ATT_MS_EXCH_ENABLED_PROTOCOLS = 131546,

            [Description("msExchExpansionServerName")]
            ATT_MS_EXCH_EXPANSION_SERVER_NAME = 1736704049,

            [Description("expirationTime")]
            ATT_MS_EXCH_EXPIRATION_TIME = 131466,

            [Description("extensionData")]
            ATT_MS_EXCH_EXTENSION_DATA = 131300,

            [Description("msExchFBURL")]
            ATT_MS_EXCH_FB_URL = 1736714001,

            [Description("folderPathname")]
            ATT_MS_EXCH_FOLDER_PATHNAME = 131409,

            [Description("formData")]
            ATT_MS_EXCH_FORM_DATA = 131679,

            [Description("forwardingAddress")]
            ATT_MS_EXCH_FORWARDING_ADDRESS = 131678,

            [Description("heuristics")]
            ATT_MS_EXCH_HEURISTICS = 131524,

            [Description("hideDLMembership")]
            ATT_MS_EXCH_HIDE_DL_MEMBERSHIP = 131369,

            [Description("msExchHideFromAddressLists")]
            ATT_MS_EXCH_HIDE_FROM_ADDRESS_LISTS = 1736704073,

            [Description("homeMDB")]
            ATT_MS_EXCH_HOME_MDB = 131316,

            [Description("homeMTA")]
            ATT_MS_EXCH_HOME_MTA = 131243,

            [Description("msExchHomeServerName")]
            ATT_MS_EXCH_HOME_SERVER_NAME = 1736704047,

            [Description("msExchIMACL")]
            ATT_MS_EXCH_IM_ACL = 1736711031,

            [Description("msExchIMAddress")]
            ATT_MS_EXCH_IM_ADDRESS = 1736711038,

            [Description("msExchIMMetaPhysicalURL")]
            ATT_MS_EXCH_IM_META_PHYSICAL_URL = 1736711035,

            [Description("msExchIMPhysicalURL")]
            ATT_MS_EXCH_IM_PHYSICAL_URL = 1736711036,

            [Description("msExchIMVirtualServer")]
            ATT_MS_EXCH_IM_VIRTUAL_SERVER = 1736711037,

            [Description("msExchIMAPOWAURLPrefixOverride")]
            ATT_MS_EXCH_IMAP_OWA_URL_PREFIX_OVERRIDE = 1030521893,

            [Description("importedFrom")]
            ATT_MS_EXCH_IMPORTED_FROM = 131335,

            [Description("msExchInconsistentState")]
            ATT_MS_EXCH_INCONSISTENT_STATE = 1736704096,

            [Description("internetEncoding")]
            ATT_MS_EXCH_INTERNET_ENCODING = 131623,

            [Description("kMServer")]
            ATT_MS_EXCH_KM_SERVER = 131512,

            [Description("msExchLabeledURI")]
            ATT_MS_EXCH_LABELEDURI = 131665,

            [Description("languageCode")]
            ATT_MS_EXCH_LANGUAGE = 131539,

            [Description("language")]
            ATT_MS_EXCH_LANGUAGE_ISO639 = 131688,

            [Description("mailNickname")]
            ATT_MS_EXCH_MAIL_NICKNAME = 131519,

            [Description("msExchMailboxFolderSet")]
            ATT_MS_EXCH_MAILBOX_FOLDER_SET = 1736715091,

            [Description("msExchMailboxGuid")]
            ATT_MS_EXCH_MAILBOX_GUID = 1736715058,

            [Description("msExchMailboxSecurityDescriptor")]
            ATT_MS_EXCH_MAILBOX_SECURITY_DESCRIPTOR = 1736704080,

            [Description("msExchMailboxUrl")]
            ATT_MS_EXCH_MAILBOX_URL = 1030521765,

            [Description("mAPIRecipient")]
            ATT_MS_EXCH_MAPI_RECIPIENT = 131443,

            [Description("msExchMasterAccountSid")]
            ATT_MS_EXCH_MASTER_ACCOUNT_SID = 1736704081,

            [Description("mDBOverHardQuotaLimit")]
            ATT_MS_EXCH_MDB_OVER_HARD_QUOTA_LIMIT = 1736715037,

            [Description("mDBOverQuotaLimit")]
            ATT_MS_EXCH_MDB_OVER_QUOTA_LIMIT = 131344,

            [Description("mDBStorageQuota")]
            ATT_MS_EXCH_MDB_STORAGE_QUOTA = 131338,

            [Description("mDBUseDefaults")]
            ATT_MS_EXCH_MDB_USE_DEFAULTS = 131381,

            [Description("msExchOmaAdminExtendedSettings")]
            ATT_MS_EXCH_OMA_ADMIN_EXTENDED_SETTINGS = 1102774398,

            [Description("msExchOmaAdminWirelessEnable")]
            ATT_MS_EXCH_OMA_ADMIN_WIRELESS_ENABLE = 1102774396,

            [Description("oOFReplyToOriginator")]
            ATT_MS_EXCH_OOF_REPLY_TO_ORIGINATOR = 131510,

            [Description("msExchOriginatingForest")]
            ATT_MS_EXCH_ORIGINATING_FOREST = 1030521980,

            [Description("msExchPfRootUrl")]
            ATT_MS_EXCH_PF_ROOT_URL = 1030521766,

            [Description("msExchPFTreeType")]
            ATT_MS_EXCH_PF_TREE_TYPE = 1736715035,

            [Description("msExchPolicyEnabled")]
            ATT_MS_EXCH_POLICY_ENABLED = 1030521710,

            [Description("msExchPolicyOptionList")]
            ATT_MS_EXCH_POLICY_OPTION_LIST = 1030521686,

            [Description("pOPCharacterSet")]
            ATT_MS_EXCH_POP_CHARACTER_SET = 131540,

            [Description("pOPContentFormat")]
            ATT_MS_EXCH_POP_CONTENT_FORMAT = 131538,

            [Description("msExchPreviousAccountSid")]
            ATT_MS_EXCH_PREVIOUS_ACCOUNT_SID = 1736704093,

            [Description("protocolSettings")]
            ATT_MS_EXCH_PROTOCOL_SETTINGS = 131600,

            [Description("msExchProxyCustomProxy")]
            ATT_MS_EXCH_PROXY_CUSTOM_PROXY = 1030521728,

            [Description("publicDelegatesBL")]
            ATT_MS_EXCH_PUBLIC_DELEGATES_BL = 131367,

            [Description("msExchQueryBaseDN")]
            ATT_MS_EXCH_QUERY_BASE_DN = 1736719008,

            [Description("msExchRecipLimit")]
            ATT_MS_EXCH_RECIP_LIMIT = 1736716523,

            [Description("replicatedObjectVersion")]
            ATT_MS_EXCH_REPLICATED_OBJECT_VERSION = 131676,

            [Description("replicationSensitivity")]
            ATT_MS_EXCH_REPLICATION_SENSITIVITY = 131295,

            [Description("replicationSignature")]
            ATT_MS_EXCH_REPLICATION_SIGNATURE = 1736704052,

            [Description("reportToOriginator")]
            ATT_MS_EXCH_REPORT_TO_ORIGINATOR = 131278,

            [Description("reportToOwner")]
            ATT_MS_EXCH_REPORT_TO_OWNER = 131279,

            [Description("msExchRequireAuthToSendTo")]
            ATT_MS_EXCH_REQUIREAUTHTOSENDTO = 594886,

            [Description("msExchResourceGUID")]
            ATT_MS_EXCH_RESOURCE_GUID = 1736713001,

            [Description("msExchResourceProperties")]
            ATT_MS_EXCH_RESOURCE_PROPERTIES = 1736713025,

            [Description("securityProtocol")]
            ATT_MS_EXCH_SECURITY_PROTOCOL = 131154,

            [Description("submissionContLength")]
            ATT_MS_EXCH_SUBMISSION_CONT_LENGTH = 131352,

            [Description("supportedAlgorithms")]
            ATT_MS_EXCH_SUPPORTED_ALGORITHMS = 131669,

            [Description("targetAddress")]
            ATT_MS_EXCH_TARGET_ADDRESS = 131424,

            [Description("msExchTUIPassword")]
            ATT_MS_EXCH_TUI_PASSWORD = 752255617,

            [Description("msExchTUISpeed")]
            ATT_MS_EXCH_TUI_SPEED = 752255619,

            [Description("msExchTUIVolume")]
            ATT_MS_EXCH_TUI_VOLUME = 752255618,

            [Description("unauthOrig")]
            ATT_MS_EXCH_UNAUTH_ORIG = 131293,

            [Description("unauthOrigBL")]
            ATT_MS_EXCH_UNAUTH_ORIG_BL = 131364,

            [Description("unmergedAtts")]
            ATT_MS_EXCH_UNMERGED_ATTS = 1736704048,

            [Description("msExchUnmergedAttsPt")]
            ATT_MS_EXCH_UNMERGED_ATTS_PT = 1736704090,

            [Description("msExchUseOAB")]
            ATT_MS_EXCH_USE_OAB = 1736704069,

            [Description("msExchUserAccountControl")]
            ATT_MS_EXCH_USER_ACCOUNT_CONTROL = 1736704101,

            [Description("msExchVoiceMailboxID")]
            ATT_MS_EXCH_VOICE_MAILBOX_ID = 752255611,

            [Description("dnQualifier")]
            ATT_MS_EXCH_X500_NC = 131581,

            [Description("msExchAddressRewriteExceptionList")]
            ATT_MS_EXCH_ADDRESS_REWRITE_EXCEPTION_LIST = 1030522151,

            [Description("msExchAddressRewriteExternalName")]
            ATT_MS_EXCH_ADDRESS_REWRITE_EXTERNAL_NAME = 1030522153,

            [Description("msExchAddressRewriteInternalName")]
            ATT_MS_EXCH_ADDRESS_REWRITE_INTERNAL_NAME = 1030522152,

            [Description("msExchAddressRewriteMappingType")]
            ATT_MS_EXCH_ADDRESS_REWRITE_MAPPING_TYPE = 1030522154,

            [Description("msExchAgentsFlags")]
            ATT_MS_EXCH_AGENTS_FLAGS = 1030522189,

            [Description("msExchAttachmentFilteringAttachmentNames")]
            ATT_MS_EXCH_ATTACHMENT_FILTERING_ATTACHMENT_NAMES = 1030522155,

            [Description("msExchAttachmentFilteringContentTypes")]
            ATT_MS_EXCH_ATTACHMENT_FILTERING_CONTENT_TYPES = 1030522157,

            [Description("msExchAttachmentFilteringFilterAction")]
            ATT_MS_EXCH_ATTACHMENT_FILTERING_FILTER_ACTION = 1030522160,

            [Description("msExchAttachmentFilteringRejectResponse")]
            ATT_MS_EXCH_ATTACHMENT_FILTERING_REJECT_RESPONSE = 1030522159,

            [Description("msExchAutoDatabaseMountAfter")]
            ATT_MS_EXCH_AUTO_DATABASE_MOUNT_AFTER = 1030522360,

            [Description("msExchAutoDiscoverAuthPackage")]
            ATT_MS_EXCH_AUTO_DISCOVER_AUTH_PACKAGE = 1030522203,

            [Description("msExchAutoDiscoverCertPrincipalName")]
            ATT_MS_EXCH_AUTO_DISCOVER_CERT_PRINCIPAL_NAME = 1030522204,

            [Description("msExchAutoDiscoverDirectoryPort")]
            ATT_MS_EXCH_AUTO_DISCOVER_DIRECTORY_PORT = 1030522200,

            [Description("msExchAutoDiscoverFlags")]
            ATT_MS_EXCH_AUTO_DISCOVER_FLAGS = 1030522205,

            [Description("msExchAutoDiscoverPort")]
            ATT_MS_EXCH_AUTO_DISCOVER_PORT = 1030522199,

            [Description("msExchAutoDiscoverReferralPort")]
            ATT_MS_EXCH_AUTO_DISCOVER_REFERRAL_PORT = 1030522201,

            [Description("msExchAutoDiscoverServer")]
            ATT_MS_EXCH_AUTO_DISCOVER_SERVER = 1030522197,

            [Description("msExchAutoDiscoverSPA")]
            ATT_MS_EXCH_AUTO_DISCOVER_SPA = 1030522202,

            [Description("msExchAutoDiscoverTTL")]
            ATT_MS_EXCH_AUTO_DISCOVER_TTL = 1030522198,

            [Description("msExchAvailabilityAccessMethod")]
            ATT_MS_EXCH_AVAILABILITY_ACCESS_METHOD = 1030522353,

            [Description("msExchAvailabilityForestName")]
            ATT_MS_EXCH_AVAILABILITY_FOREST_NAME = 1030522349,

            [Description("msExchAvailabilityUseServiceAccount")]
            ATT_MS_EXCH_AVAILABILITY_USE_SERVICE_ACCOUNT = 1030522352,

            [Description("msExchAvailabilityUserName")]
            ATT_MS_EXCH_AVAILABILITY_USER_NAME = 1030522350,

            [Description("msExchAvailabilityUserPassword")]
            ATT_MS_EXCH_AVAILABILITY_USER_PASSWORD = 1030522351,

            [Description("msExchClusterReplicationOrderedPrefixes")]
            ATT_MS_EXCH_CLUSTER_REPLICATION_ORDERED_PREFIXES = 1030522357,

            [Description("msExchClusterStorageType")]
            ATT_MS_EXCH_CLUSTER_STORAGE_TYPE = 1030522358,

            [Description("msExchCopyEDBFile")]
            ATT_MS_EXCH_COPY_EDB_FILE = 1030522098,

            [Description("msExchCurrentServerRoles")]
            ATT_MS_EXCH_CURRENT_SERVER_ROLES = 1030522149,

            [Description("msExchDataLossForAutoDatabaseMount")]
            ATT_MS_EXCH_DATA_LOSS_FOR_AUTO_DATABASE_MOUNT = 1030522359,

            [Description("msExchDSNFlags")]
            ATT_MS_EXCH_DSN_FLAGS = 1030522281,

            [Description("msExchDSNSendCopyToAdmin")]
            ATT_MS_EXCH_DSN_SEND_COPY_TO_ADMIN = 1030522373,

            [Description("msExchELCFlags")]
            ATT_MS_EXCH_ELC_FLAGS = 1030522136,

            [Description("msExchELCFolderType")]
            ATT_MS_EXCH_ELC_FOLDER_TYPE = 1030522137,

            [Description("msExchELCLabel")]
            ATT_MS_EXCH_ELC_LABEL = 1030522196,

            [Description("msExchELCSchedule")]
            ATT_MS_EXCH_ELC_SCHEDULE = 1030522138,

            [Description("msExchESEParamCopyLogFilePath")]
            ATT_MS_EXCH_ESE_PARAM_COPY_LOG_FILE_PATH = 1030522095,

            [Description("msExchESEParamCopySystemPath")]
            ATT_MS_EXCH_ESE_PARAM_COPY_SYSTEM_PATH = 1030522096,

            [Description("msExchEventHistoryRetentionPeriod")]
            ATT_MS_EXCH_EVENT_HISTORY_RETENTION_PERIOD = 1030522150,

            [Description("msExchExternalAuthenticationMethods")]
            ATT_MS_EXCH_EXTERNAL_AUTHENTICATION_METHODS = 1030522146,

            [Description("msExchExternalHostName")]
            ATT_MS_EXCH_EXTERNAL_HOST_NAME = 1030522144,

            [Description("msExchExternalOOFOptions")]
            ATT_MS_EXCH_EXTERNAL_OOF_OPTIONS = 1030522142,

            [Description("msExchHasLocalCopy")]
            ATT_MS_EXCH_HAS_LOCAL_COPY = 1030522097,

            [Description("msExchInternalAuthenticationMethods")]
            ATT_MS_EXCH_INTERNAL_AUTHENTICATION_METHODS = 1030522145,

            [Description("msExchInternalHostName")]
            ATT_MS_EXCH_INTERNAL_HOST_NAME = 1030522143,

            [Description("msExchJournalingReportNDRTo")]
            ATT_MS_EXCH_JOURNALING_REPORT_NDR_TO = 1030522161,

            [Description("msExchMaxStoresTotal")]
            ATT_MS_EXCH_MAX_STORES_TOTAL = 1030522092,

            [Description("msExchMDBRulesQuota")]
            ATT_MS_EXCH_MDB_RULES_QUOTA = 1030522093,

            [Description("msExchMessageClassificationConfidentialityAction")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_CONFIDENTIALITY_ACTION = 1030522324,

            [Description("msExchMessageClassificationDisplayPrecedence")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_DISPLAY_PRECEDENCE = 1030522323,

            [Description("msExchMessageClassificationFlags")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_FLAGS = 1030522326,

            [Description("msExchMessageClassificationID")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_ID = 1030522321,

            [Description("msExchMessageClassificationIntegrityAction")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_INTEGRITY_ACTION = 1030522325,

            [Description("msExchMessageClassificationLocale")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_LOCALE = 1030522327,

            [Description("msExchMessageClassificationURL")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_URL = 1030522329,

            [Description("msExchMessageClassificationVersion")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_VERSION = 1030522322,

            [Description("msExchMessageHygieneBitmask")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BITMASK = 1030522297,

            [Description("msExchMessageHygieneBlockedDomain")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BLOCKED_DOMAIN = 1030522301,

            [Description("msExchMessageHygieneBlockedDomainAndSubdomains")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BLOCKED_DOMAIN_AND_SUBDOMAINS = 1030522303,

            [Description("msExchMessageHygieneBlockedRecipient")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BLOCKED_RECIPIENT = 1030522307,

            [Description("msExchMessageHygieneBlockedSender")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BLOCKED_SENDER = 1030522300,

            [Description("msExchMessageHygieneBlockedSenderAction")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BLOCKED_SENDER_ACTION = 1030522299,

            [Description("msExchMessageHygieneBypassedRecipient")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BYPASSED_RECIPIENT = 1030522288,

            [Description("msExchMessageHygieneBypassedSenderDomain")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BYPASSED_SENDER_DOMAIN = 1030522289,

            [Description("msExchMessageHygieneContentFilterLocation")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_CONTENT_FILTER_LOCATION = 1030522308,

            [Description("msExchMessageHygieneCustomWeightEntry")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_CUSTOM_WEIGHT_ENTRY = 1030522293,

            [Description("msExchMessageHygieneDelayHours")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_DELAY_HOURS = 1030522298,

            [Description("msExchMessageHygieneIPAddress")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_IP_ADDRESS = 1030522304,

            [Description("msExchMessageHygieneLookupDomain")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_LOOKUP_DOMAIN = 1030522294,

            [Description("msExchMessageHygienePriority")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_PRIORITY = 1030522296,

            [Description("msExchMessageHygieneProviderFlags")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_PROVIDER_FLAGS = 1030522306,

            [Description("msExchMessageHygieneProviderName")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_PROVIDER_NAME = 1030522305,

            [Description("msExchMessageHygieneRejectionMessage")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_REJECTION_MESSAGE = 1030522292,

            [Description("msExchMessageHygieneResultType")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_RESULT_TYPE = 1030522295,

            [Description("msExchMessageHygieneSpoofedDomainAction")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_SPOOFED_DOMAIN_ACTION = 1030522286,

            [Description("msExchMessageHygieneTempErrorAction")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_TEMP_ERROR_ACTION = 1030522287,

            [Description("msExchMetabasePath")]
            ATT_MS_EXCH_METABASE_PATH = 1030522147,

            [Description("msExchMobileAllowedDeviceIDs")]
            ATT_MS_EXCH_MOBILE_ALLOWED_DEVICE_IDS = 1030522346,

            [Description("msExchMobileClientCertTemplateName")]
            ATT_MS_EXCH_MOBILE_CLIENT_CERT_TEMPLATE_NAME = 1030522332,

            [Description("msExchMobileClientCertificateAuthorityURL")]
            ATT_MS_EXCH_MOBILE_CLIENT_CERTIFICATE_AUTHORITY_URL = 1030522331,

            [Description("msExchMobileClientFlags")]
            ATT_MS_EXCH_MOBILE_CLIENT_FLAGS = 1030522330,

            [Description("msExchMobileDebugLogging")]
            ATT_MS_EXCH_MOBILE_DEBUG_LOGGING = 1030522347,

            [Description("msExchMobileDefaultEmailTruncationSize")]
            ATT_MS_EXCH_MOBILE_DEFAULT_EMAIL_TRUNCATION_SIZE = 1030522340,

            [Description("msExchMobileDevicePolicyRefreshInterval")]
            ATT_MS_EXCH_MOBILE_DEVICE_POLICY_REFRESH_INTERVAL = 1030522333,

            [Description("msExchMobileFlags")]
            ATT_MS_EXCH_MOBILE_FLAGS = 1030522334,

            [Description("msExchMobileInitialMaxAttachmentSize")]
            ATT_MS_EXCH_MOBILE_INITIAL_MAX_ATTACHMENT_SIZE = 1030522341,

            [Description("msExchMobileMaxCalendarDays")]
            ATT_MS_EXCH_MOBILE_MAX_CALENDAR_DAYS = 1030522342,

            [Description("msExchMobileMaxDevicePasswordFailedAttempts")]
            ATT_MS_EXCH_MOBILE_MAX_DEVICE_PASSWORD_FAILED_ATTEMPTS = 1030522337,

            [Description("msExchMobileMaxEmailDays")]
            ATT_MS_EXCH_MOBILE_MAX_EMAIL_DAYS = 1030522339,

            [Description("msExchMobileMaxInactivityTimeDeviceLock")]
            ATT_MS_EXCH_MOBILE_MAX_INACTIVITY_TIME_DEVICE_LOCK = 1030522336,

            [Description("msExchMobileMinDevicePasswordLength")]
            ATT_MS_EXCH_MOBILE_MIN_DEVICE_PASSWORD_LENGTH = 1030522335,

            [Description("msExchOABFlags")]
            ATT_MS_EXCH_OAB_FLAGS = 1030522190,

            [Description("msExchOWAActionForUnknownFileAndMIMETypes")]
            ATT_MS_EXCH_OWA_ACTION_FOR_UNKNOWN_FILE_AND_MIME_TYPES = 1030522380,

            [Description("msExchOWAClientAuthCleanupLevel")]
            ATT_MS_EXCH_OWA_CLIENT_AUTH_CLEANUP_LEVEL = 1030522382,

            [Description("msExchOWADefaultClientLanguage")]
            ATT_MS_EXCH_OWA_DEFAULT_CLIENT_LANGUAGE = 1030522388,

            [Description("msExchOWADefaultTheme")]
            ATT_MS_EXCH_OWA_DEFAULT_THEME = 1030522390,

            [Description("msExchOWAExchwebProxyDestination")]
            ATT_MS_EXCH_OWA_EXCHWEB_PROXY_DESTINATION = 1030522375,

            [Description("msExchOWAFileAccessControlOnPrivateComputers")]
            ATT_MS_EXCH_OWA_FILE_ACCESS_CONTROL_ON_PRIVATE_COMPUTERS = 1030522378,

            [Description("msExchOWAFileAccessControlOnPublicComputers")]
            ATT_MS_EXCH_OWA_FILE_ACCESS_CONTROL_ON_PUBLIC_COMPUTERS = 1030522377,

            [Description("msExchOWAFilterWebBeacons")]
            ATT_MS_EXCH_OWA_FILTER_WEB_BEACONS = 1030522384,

            [Description("msExchOWAGzipLevel")]
            ATT_MS_EXCH_OWA_GZIP_LEVEL = 1030522383,

            [Description("msExchOWALogonAndErrorLanguage")]
            ATT_MS_EXCH_OWA_LOGON_AND_ERROR_LANGUAGE = 1030522389,

            [Description("msExchOWALogonFormat")]
            ATT_MS_EXCH_OWA_LOGON_FORMAT = 1030522381,

            [Description("msExchOWAMaxTranscodableDocSize")]
            ATT_MS_EXCH_OWA_MAX_TRANSCODABLE_DOC_SIZE = 1030522391,

            [Description("msExchOWANotificationInterval")]
            ATT_MS_EXCH_OWA_NOTIFICATION_INTERVAL = 1030522385,

            [Description("msExchOWAOutboundCharset")]
            ATT_MS_EXCH_OWA_OUTBOUND_CHARSET = 1030522403,

            [Description("msExchOWARedirectToOptimalOWAServer")]
            ATT_MS_EXCH_OWA_REDIRECT_TO_OPTIMAL_OWA_SERVER = 1030522386,

            [Description("msExchOWARemoteDocumentsActionForUnknownServers")]
            ATT_MS_EXCH_OWA_REMOTE_DOCUMENTS_ACTION_FOR_UNKNOWN_SERVERS = 1030522379,

            [Description("msExchOWAUseGB18030")]
            ATT_MS_EXCH_OWA_USE_GB18030 = 1030522404,

            [Description("msExchOWAUseISO885915")]
            ATT_MS_EXCH_OWA_USE_ISO8859_15 = 1030522405,

            [Description("msExchOWAUserContextTimeout")]
            ATT_MS_EXCH_OWA_USER_CONTEXT_TIMEOUT = 1030522387,

            [Description("msExchOWAVersion")]
            ATT_MS_EXCH_OWA_VERSION = 1030522374,

            [Description("msExchOWAVirtualDirectoryType")]
            ATT_MS_EXCH_OWA_VIRTUAL_DIRECTORY_TYPE = 1030522376,

            [Description("msExchQueryFilter")]
            ATT_MS_EXCH_QUERY_FILTER = 1030522209,

            [Description("msExchResourceAddressLists")]
            ATT_MS_EXCH_RESOURCE_ADDRESS_LISTS = 1030522148,

            [Description("msExchSenderReputationCiscoPorts")]
            ATT_MS_EXCH_SENDER_REPUTATION_CISCO_PORTS = 1030522179,

            [Description("msExchSenderReputationHttpConnectPorts")]
            ATT_MS_EXCH_SENDER_REPUTATION_HTTP_CONNECT_PORTS = 1030522177,

            [Description("msExchSenderReputationHttpPostPorts")]
            ATT_MS_EXCH_SENDER_REPUTATION_HTTP_POST_PORTS = 1030522178,

            [Description("msExchSenderReputationMaxDownloadInterval")]
            ATT_MS_EXCH_SENDER_REPUTATION_MAX_DOWNLOAD_INTERVAL = 1030522187,

            [Description("msExchSenderReputationMaxIdleTime")]
            ATT_MS_EXCH_SENDER_REPUTATION_MAX_IDLE_TIME = 1030522173,

            [Description("msExchSenderReputationMaxPendingOperations")]
            ATT_MS_EXCH_SENDER_REPUTATION_MAX_PENDING_OPERATIONS = 1030522182,

            [Description("msExchSenderReputationMaxWorkQueueSize")]
            ATT_MS_EXCH_SENDER_REPUTATION_MAX_WORK_QUEUE_SIZE = 1030522172,

            [Description("msExchSenderReputationMinDownloadInterval")]
            ATT_MS_EXCH_SENDER_REPUTATION_MIN_DOWNLOAD_INTERVAL = 1030522186,

            [Description("msExchSenderReputationMinMessagePerTimeSlice")]
            ATT_MS_EXCH_SENDER_REPUTATION_MIN_MESSAGE_PER_TIME_SLICE = 1030522166,

            [Description("msExchSenderReputationMinMessagesPerDatabaseTransaction")]
            ATT_MS_EXCH_SENDER_REPUTATION_MIN_MESSAGES_PER_DATABASE_TRANSACTION = 1030522164,

            [Description("msExchSenderReputationMinReverseDnsQueryPeriod")]
            ATT_MS_EXCH_SENDER_REPUTATION_MIN_REVERSE_DNS_QUERY_PERIOD = 1030522170,

            [Description("msExchSenderReputationOpenProxyFlags")]
            ATT_MS_EXCH_SENDER_REPUTATION_OPEN_PROXY_FLAGS = 1030522169,

            [Description("msExchSenderReputationOpenProxyRescanInterval")]
            ATT_MS_EXCH_SENDER_REPUTATION_OPEN_PROXY_RESCAN_INTERVAL = 1030522168,

            [Description("msExchSenderReputationProxyServerIP")]
            ATT_MS_EXCH_SENDER_REPUTATION_PROXY_SERVER_IP = 1030522183,

            [Description("msExchSenderReputationProxyServerPort")]
            ATT_MS_EXCH_SENDER_REPUTATION_PROXY_SERVER_PORT = 1030522185,

            [Description("msExchSenderReputationProxyServerType")]
            ATT_MS_EXCH_SENDER_REPUTATION_PROXY_SERVER_TYPE = 1030522184,

            [Description("msExchSenderReputationSenderBlockingPeriod")]
            ATT_MS_EXCH_SENDER_REPUTATION_SENDER_BLOCKING_PERIOD = 1030522171,

            [Description("msExchSenderReputationServiceUrl")]
            ATT_MS_EXCH_SENDER_REPUTATION_SERVICE_URL = 1030522407,

            [Description("msExchSenderReputationSocks4Ports")]
            ATT_MS_EXCH_SENDER_REPUTATION_SOCKS4_PORTS = 1030522174,

            [Description("msExchSenderReputationSocks5Ports")]
            ATT_MS_EXCH_SENDER_REPUTATION_SOCKS5_PORTS = 1030522175,

            [Description("msExchSenderReputationSrlBlockThreshold")]
            ATT_MS_EXCH_SENDER_REPUTATION_SRL_BLOCK_THRESHOLD = 1030522165,

            [Description("msExchSenderReputationSrlSettingsDatabaseFileName")]
            ATT_MS_EXCH_SENDER_REPUTATION_SRL_SETTINGS_DATABASE_FILE_NAME = 1030522188,

            [Description("msExchSenderReputationTablePurgeInterval")]
            ATT_MS_EXCH_SENDER_REPUTATION_TABLE_PURGE_INTERVAL = 1030522181,

            [Description("msExchSenderReputationTelnetPorts")]
            ATT_MS_EXCH_SENDER_REPUTATION_TELNET_PORTS = 1030522180,

            [Description("msExchSenderReputationTimeSliceInterval")]
            ATT_MS_EXCH_SENDER_REPUTATION_TIME_SLICE_INTERVAL = 1030522167,

            [Description("msExchSenderReputationWingatePorts")]
            ATT_MS_EXCH_SENDER_REPUTATION_WINGATE_PORTS = 1030522176,

            [Description("msExchServerRedundantMachines")]
            ATT_MS_EXCH_SERVER_REDUNDANT_MACHINES = 1030522356,

            [Description("msExchSmtpReceiveAdvertisedDomain")]
            ATT_MS_EXCH_SMTP_RECEIVE_ADVERTISED_DOMAIN = 1030522219,

            [Description("msExchSmtpReceiveBanner")]
            ATT_MS_EXCH_SMTP_RECEIVE_BANNER = 1030522236,

            [Description("msExchSmtpReceiveBindings")]
            ATT_MS_EXCH_SMTP_RECEIVE_BINDINGS = 1030522220,

            [Description("msExchSmtpReceiveConnectionTimeout")]
            ATT_MS_EXCH_SMTP_RECEIVE_CONNECTION_TIMEOUT = 1030522223,

            [Description("msExchSmtpReceiveEnabled")]
            ATT_MS_EXCH_SMTP_RECEIVE_ENABLED = 1030522222,

            [Description("msExchSmtpReceiveMaxHeaderSize")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_HEADER_SIZE = 1030522226,

            [Description("msExchSmtpReceiveMaxHopCount")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_HOP_COUNT = 1030522227,

            [Description("msExchSmtpReceiveMaxInboundConnections")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_INBOUND_CONNECTIONS = 1030522224,

            [Description("msExchSmtpReceiveMaxInboundConnectionsPerSource")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_INBOUND_CONNECTIONS_PER_SOURCE = 1030522225,

            [Description("msExchSmtpReceiveMaxLocalHopCount")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_LOCAL_HOP_COUNT = 1030522228,

            [Description("msExchSmtpReceiveMaxLogonFailures")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_LOGON_FAILURES = 1030522229,

            [Description("msExchSmtpReceiveMaxMessageSize")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_MESSAGE_SIZE = 1030522230,

            [Description("msExchSmtpReceiveMaxMessagesPerConnection")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_MESSAGES_PER_CONNECTION = 1030522231,

            [Description("msExchSmtpReceiveMaxProtocolErrors")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_PROTOCOL_ERRORS = 1030522232,

            [Description("msExchSmtpReceiveMaxRecipientsPerMessage")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_RECIPIENTS_PER_MESSAGE = 1030522233,

            [Description("msExchSmtpReceiveProtocolLoggingLevel")]
            ATT_MS_EXCH_SMTP_RECEIVE_PROTOCOL_LOGGING_LEVEL = 1030522234,

            [Description("msExchSmtpReceiveProtocolOptions")]
            ATT_MS_EXCH_SMTP_RECEIVE_PROTOCOL_OPTIONS = 1030522239,

            [Description("msExchSmtpReceiveProtocolRestrictions")]
            ATT_MS_EXCH_SMTP_RECEIVE_PROTOCOL_RESTRICTIONS = 1030522240,

            [Description("msExchSMTPReceiveRelayControl")]
            ATT_MS_EXCH_SMTP_RECEIVE_RELAY_CONTROL = 1030522368,

            [Description("msExchSmtpReceiveRemoteIPRanges")]
            ATT_MS_EXCH_SMTP_RECEIVE_REMOTE_IP_RANGES = 1030522235,

            [Description("msExchSmtpReceiveSecurityDescriptor")]
            ATT_MS_EXCH_SMTP_RECEIVE_SECURITY_DESCRIPTOR = 1030522241,

            [Description("msExchSmtpReceiveTarpitInterval")]
            ATT_MS_EXCH_SMTP_RECEIVE_TARPIT_INTERVAL = 1030522237,

            [Description("msExchSmtpReceiveTlsCertificateName")]
            ATT_MS_EXCH_SMTP_RECEIVE_TLS_CERTIFICATE_NAME = 1030522238,

            [Description("msExchSmtpReceiveType")]
            ATT_MS_EXCH_SMTP_RECEIVE_TYPE = 1030522221,

            [Description("msExchSmtpSendAdvertisedDomain")]
            ATT_MS_EXCH_SMTP_SEND_ADVERTISED_DOMAIN = 1030522212,

            [Description("msExchSmtpSendBindingIPAddress")]
            ATT_MS_EXCH_SMTP_SEND_BINDING_IP_ADDRESS = 1030522217,

            [Description("msExchSmtpSendConnectionTimeout")]
            ATT_MS_EXCH_SMTP_SEND_CONNECTION_TIMEOUT = 1030522214,

            [Description("msExchSmtpSendEnabled")]
            ATT_MS_EXCH_SMTP_SEND_ENABLED = 1030522213,

            [Description("msExchSmtpSendFlags")]
            ATT_MS_EXCH_SMTP_SEND_FLAGS = 1030522215,

            [Description("msExchSmtpSendPort")]
            ATT_MS_EXCH_SMTP_SEND_PORT = 1030522211,

            [Description("msExchSmtpSendProtocolLoggingLevel")]
            ATT_MS_EXCH_SMTP_SEND_PROTOCOL_LOGGING_LEVEL = 1030522216,

            [Description("msExchSmtpSendType")]
            ATT_MS_EXCH_SMTP_SEND_TYPE = 1030522210,

            [Description("msExchTransportDelayNotificationTimeout")]
            ATT_MS_EXCH_TRANSPORT_DELAY_NOTIFICATION_TIMEOUT = 1030522313,

            [Description("msExchTransportExternalDefaultLanguage")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_DEFAULT_LANGUAGE = 1030522271,

            [Description("msExchTransportExternalDNSAdapterGuid")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_DNS_ADAPTER_GUID = 1030522369,

            [Description("msExchTransportExternalDNSProtocolOption")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_DNS_PROTOCOL_OPTION = 1030522370,

            [Description("msExchTransportExternalDSNReportingAuthority")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_DSN_REPORTING_AUTHORITY = 1030522273,

            [Description("msExchTransportExternalMaxDSNMessageAttachmentSize")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_MAX_DSN_MESSAGE_ATTACHMENT_SIZE = 1030522269,

            [Description("msExchTransportExternalPostmasterAddress")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_POSTMASTER_ADDRESS = 1030522274,

            [Description("msExchTransportFlags")]
            ATT_MS_EXCH_TRANSPORT_FLAGS = 1030522259,

            [Description("msExchTransportInternalDefaultLanguage")]
            ATT_MS_EXCH_TRANSPORT_INTERNAL_DEFAULT_LANGUAGE = 1030522272,

            [Description("msExchTransportInternalDNSAdapterGuid")]
            ATT_MS_EXCH_TRANSPORT_INTERNAL_DNS_ADAPTER_GUID = 1030522256,

            [Description("msExchTransportInternalDNSProtocolOption")]
            ATT_MS_EXCH_TRANSPORT_INTERNAL_DNS_PROTOCOL_OPTION = 1030522260,

            [Description("msExchTransportInternalDNSServers")]
            ATT_MS_EXCH_TRANSPORT_INTERNAL_DNS_SERVERS = 1030522258,

            [Description("msExchTransportInternalDSNReportingAuthority")]
            ATT_MS_EXCH_TRANSPORT_INTERNAL_DSN_REPORTING_AUTHORITY = 1030522255,

            [Description("msExchTransportInternalMaxDSNMessageAttachmentSize")]
            ATT_MS_EXCH_TRANSPORT_INTERNAL_MAX_DSN_MESSAGE_ATTACHMENT_SIZE = 1030522270,

            [Description("msExchTransportInternalPostmasterAddress")]
            ATT_MS_EXCH_TRANSPORT_INTERNAL_POSTMASTER_ADDRESS = 1030522275,

            [Description("msExchTransportMaxConcurrentMailboxDeliveries")]
            ATT_MS_EXCH_TRANSPORT_MAX_CONCURRENT_MAILBOX_DELIVERIES = 1030522309,

            [Description("msExchTransportMaxMessageTrackingDirectorySize")]
            ATT_MS_EXCH_TRANSPORT_MAX_MESSAGE_TRACKING_DIRECTORY_SIZE = 1030522278,

            [Description("msExchTransportMaxMessageTrackingFileSize")]
            ATT_MS_EXCH_TRANSPORT_MAX_MESSAGE_TRACKING_FILE_SIZE = 1030522279,

            [Description("msExchTransportMaxMessageTrackingLogAge")]
            ATT_MS_EXCH_TRANSPORT_MAX_MESSAGE_TRACKING_LOG_AGE = 1030522277,

            [Description("msExchTransportMaxPickupDirectoryHeaderSize")]
            ATT_MS_EXCH_TRANSPORT_MAX_PICKUP_DIRECTORY_HEADER_SIZE = 1030522263,

            [Description("msExchTransportMaxPickupDirectoryMessageSize")]
            ATT_MS_EXCH_TRANSPORT_MAX_PICKUP_DIRECTORY_MESSAGE_SIZE = 1030522262,

            [Description("msExchTransportMaxPickupDirectoryRecipients")]
            ATT_MS_EXCH_TRANSPORT_MAX_PICKUP_DIRECTORY_RECIPIENTS = 1030522264,

            [Description("msExchTransportMaxQueueIdleTime")]
            ATT_MS_EXCH_TRANSPORT_MAX_QUEUE_IDLE_TIME = 1030522316,

            [Description("msExchTransportMaxReceiveProtocolLogAge")]
            ATT_MS_EXCH_TRANSPORT_MAX_RECEIVE_PROTOCOL_LOG_AGE = 1030522249,

            [Description("msExchTransportMaxReceiveProtocolLogDirectorySize")]
            ATT_MS_EXCH_TRANSPORT_MAX_RECEIVE_PROTOCOL_LOG_DIRECTORY_SIZE = 1030522251,

            [Description("msExchTransportMaxReceiveProtocolLogFileSize")]
            ATT_MS_EXCH_TRANSPORT_MAX_RECEIVE_PROTOCOL_LOG_FILE_SIZE = 1030522250,

            [Description("msExchTransportMaxSendProtocolLogAge")]
            ATT_MS_EXCH_TRANSPORT_MAX_SEND_PROTOCOL_LOG_AGE = 1030522252,

            [Description("msExchTransportMaxSendProtocolLogDirectorySize")]
            ATT_MS_EXCH_TRANSPORT_MAX_SEND_PROTOCOL_LOG_DIRECTORY_SIZE = 1030522254,

            [Description("msExchTransportMaxSendProtocolLogFileSize")]
            ATT_MS_EXCH_TRANSPORT_MAX_SEND_PROTOCOL_LOG_FILE_SIZE = 1030522253,

            [Description("msExchTransportMessageExpirationTimeout")]
            ATT_MS_EXCH_TRANSPORT_MESSAGE_EXPIRATION_TIMEOUT = 1030522312,

            [Description("msExchTransportMessageRetryInterval")]
            ATT_MS_EXCH_TRANSPORT_MESSAGE_RETRY_INTERVAL = 1030522246,

            [Description("msExchTransportMessageTrackingPath")]
            ATT_MS_EXCH_TRANSPORT_MESSAGE_TRACKING_PATH = 1030522276,

            [Description("msExchTransportOutboundConnectionFailureRetryInterval")]
            ATT_MS_EXCH_TRANSPORT_OUTBOUND_CONNECTION_FAILURE_RETRY_INTERVAL = 1030522245,

            [Description("msExchTransportOutboundProtocolLoggingLevel")]
            ATT_MS_EXCH_TRANSPORT_OUTBOUND_PROTOCOL_LOGGING_LEVEL = 1030522371,

            [Description("msExchTransportPerQueueMessageDehydrationThreshold")]
            ATT_MS_EXCH_TRANSPORT_PER_QUEUE_MESSAGE_DEHYDRATION_THRESHOLD = 1030522318,

            [Description("msExchTransportPickupDirectoryPath")]
            ATT_MS_EXCH_TRANSPORT_PICKUP_DIRECTORY_PATH = 1030522261,

            [Description("msExchTransportPoisonMessageThreshold")]
            ATT_MS_EXCH_TRANSPORT_POISON_MESSAGE_THRESHOLD = 1030522314,

            [Description("msExchTransportReceiveProtocolLogPath")]
            ATT_MS_EXCH_TRANSPORT_RECEIVE_PROTOCOL_LOG_PATH = 1030522248,

            [Description("msExchTransportRulePriority")]
            ATT_MS_EXCH_TRANSPORT_RULE_PRIORITY = 1030522140,

            [Description("msExchTransportRuleXml")]
            ATT_MS_EXCH_TRANSPORT_RULE_XML = 1030522141,

            [Description("msExchTransportSecurityDescriptor")]
            ATT_MS_EXCH_TRANSPORT_SECURITY_DESCRIPTOR = 1030522372,

            [Description("msExchTransportSendProtocolLogPath")]
            ATT_MS_EXCH_TRANSPORT_SEND_PROTOCOL_LOG_PATH = 1030522247,

            [Description("msExchTransportTotalQueueMessageDehydrationThreshold")]
            ATT_MS_EXCH_TRANSPORT_TOTAL_QUEUE_MESSAGE_DEHYDRATION_THRESHOLD = 1030522317,

            [Description("msExchTransportTransientFailureRetryCount")]
            ATT_MS_EXCH_TRANSPORT_TRANSIENT_FAILURE_RETRY_COUNT = 1030522244,

            [Description("msExchTransportTransientFailureRetryInterval")]
            ATT_MS_EXCH_TRANSPORT_TRANSIENT_FAILURE_RETRY_INTERVAL = 1030522243,

            [Description("msExchUMAllowedInCountryGroups")]
            ATT_MS_EXCH_UM_ALLOWED_IN_COUNTRY_GROUPS = 1030522123,

            [Description("msExchUMAllowedInternationalGroups")]
            ATT_MS_EXCH_UM_ALLOWED_INTERNATIONAL_GROUPS = 1030522124,

            [Description("msExchUMASREnabled")]
            ATT_MS_EXCH_UM_ASR_ENABLED = 1030522104,

            [Description("msExchUMAvailableInCountryGroups")]
            ATT_MS_EXCH_UM_AVAILABLE_IN_COUNTRY_GROUPS = 1030522121,

            [Description("msExchUMAvailableInternationalGroups")]
            ATT_MS_EXCH_UM_AVAILABLE_INTERNATIONAL_GROUPS = 1030522122,

            [Description("msExchUMCallSomeoneEnabled")]
            ATT_MS_EXCH_UM_CALL_SOMEONE_ENABLED = 1030522108,

            [Description("msExchUMCallSomeoneScope")]
            ATT_MS_EXCH_UM_CALL_SOMEONE_SCOPE = 1030522130,

            [Description("msExchUMCountryCode")]
            ATT_MS_EXCH_UM_COUNTRY_CODE = 1030522118,

            [Description("msExchUMDialPlanSubscribersAllowed")]
            ATT_MS_EXCH_UM_DIAL_PLAN_SUBSCRIBERS_ALLOWED = 1030522110,

            [Description("msExchUMDisambiguationField")]
            ATT_MS_EXCH_UM_DISAMBIGUATION_FIELD = 1030522126,

            [Description("msExchUMEquivalenceDialPlan")]
            ATT_MS_EXCH_UM_EQUIVALENCE_DIAL_PLAN = 1030522366,

            [Description("msExchUMExtensionLengthNumbersAllowed")]
            ATT_MS_EXCH_UM_EXTENSION_LENGTH_NUMBERS_ALLOWED = 1030522111,

            [Description("msExchUMGrammarGenerationSchedule")]
            ATT_MS_EXCH_UM_GRAMMAR_GENERATION_SCHEDULE = 1030522365,

            [Description("msExchUMInCountryNumberFormat")]
            ATT_MS_EXCH_UM_IN_COUNTRY_NUMBER_FORMAT = 1030522119,

            [Description("msExchUMInfoAnnouncementFile")]
            ATT_MS_EXCH_UM_INFO_ANNOUNCEMENT_FILE = 1030522113,

            [Description("msExchUMInfoAnnouncementStatus")]
            ATT_MS_EXCH_UM_INFO_ANNOUNCEMENT_STATUS = 1030522107,

            [Description("msExchUMInternationalAccessCode")]
            ATT_MS_EXCH_UM_INTERNATIONAL_ACCESS_CODE = 1030522116,

            [Description("msExchUMInternationalNumberFormat")]
            ATT_MS_EXCH_UM_INTERNATIONAL_NUMBER_FORMAT = 1030522120,

            [Description("msExchUMIPGatewayStatus")]
            ATT_MS_EXCH_UM_IP_GATEWAY_STATUS = 1030522131,

            [Description("msExchUMLogonFailuresBeforePINReset")]
            ATT_MS_EXCH_UM_LOGON_FAILURES_BEFORE_PIN_RESET = 1030522402,

            [Description("msExchUMMaximumASRSessionsAllowed")]
            ATT_MS_EXCH_UM_MAXIMUM_ASR_SESSIONS_ALLOWED = 1030522103,

            [Description("msExchUMMaximumCallsAllowed")]
            ATT_MS_EXCH_UM_MAXIMUM_CALLS_ALLOWED = 1030522100,

            [Description("msExchUMMaximumFaxCallsAllowed")]
            ATT_MS_EXCH_UM_MAXIMUM_FAX_CALLS_ALLOWED = 1030522101,

            [Description("msExchUMMaximumTTSSessionsAllowed")]
            ATT_MS_EXCH_UM_MAXIMUM_TTS_SESSIONS_ALLOWED = 1030522102,

            [Description("msExchUMNationalNumberPrefix")]
            ATT_MS_EXCH_UM_NATIONAL_NUMBER_PREFIX = 1030522117,

            [Description("msExchUMNDRReqEnabled")]
            ATT_MS_EXCH_UM_NDR_REQ_ENABLED = 1030522105,

            [Description("msExchUMOperatorExtension")]
            ATT_MS_EXCH_UM_OPERATOR_EXTENSION = 1030522114,

            [Description("msExchUMOutcallsAllowed")]
            ATT_MS_EXCH_UM_OUTCALLS_ALLOWED = 1030522132,

            [Description("msExchUMOverrideExtension")]
            ATT_MS_EXCH_UM_OVERRIDE_EXTENSION = 1030522115,

            [Description("msExchUMPhoneContext")]
            ATT_MS_EXCH_UM_PHONE_CONTEXT = 1030522125,

            [Description("msExchUMSendVoiceMessageEnabled")]
            ATT_MS_EXCH_UM_SEND_VOICE_MESSAGE_ENABLED = 1030522109,

            [Description("msExchUMSendVoiceMessageScope")]
            ATT_MS_EXCH_UM_SEND_VOICE_MESSAGE_SCOPE = 1030522127,

            [Description("msExchUMServerStatus")]
            ATT_MS_EXCH_UM_SERVER_STATUS = 1030522099,

            [Description("msExchUMTimeZone")]
            ATT_MS_EXCH_UM_TIME_ZONE = 1030522361,

            [Description("msExchUMWelcomeGreetingEnabled")]
            ATT_MS_EXCH_UM_WELCOME_GREETING_ENABLED = 1030522106,

            [Description("msExchUMWelcomeGreetingFile")]
            ATT_MS_EXCH_UM_WELCOME_GREETING_FILE = 1030522112,

            [Description("msExchMobileMailboxPolicyLink")]
            ATT_MS_EXCH_MOBILE_MAILBOX_POLICY_LINK = 1030522348,

            [Description("msExchMobileMailboxPolicyBL")]
            ATT_MS_EXCH_MOBILE_MAILBOX_POLICY_BL = 1030522406,

            [Description("msExchAvailabilityPerUserAccount")]
            ATT_MS_EXCH_AVAILABILITY_PER_USER_ACCOUNT = 1030522354,

            [Description("msExchAvailabilityOrgWideAccount")]
            ATT_MS_EXCH_AVAILABILITY_ORG_WIDE_ACCOUNT = 1030522355,

            [Description("msExchUMDTMFFallbackAutoAttendantLink")]
            ATT_MS_EXCH_UM_DTMF_FALLBACK_AUTO_ATTENDANT_LINK = 1030522362,

            [Description("msExchUMDTMFFallbackAutoAttendantBL")]
            ATT_MS_EXCH_UM_DTMF_FALLBACK_AUTO_ATTENDANT_BL = 1030522363,

            [Description("msExchOWATranscodingFileTypes")]
            ATT_MS_EXCH_OWA_TRANSCODING_FILE_TYPES = 1030522392,

            [Description("msExchOWAAllowedFileTypes")]
            ATT_MS_EXCH_OWA_ALLOWED_FILE_TYPES = 1030522393,

            [Description("msExchOWAAllowedMimeTypes")]
            ATT_MS_EXCH_OWA_ALLOWED_MIME_TYPES = 1030522394,

            [Description("msExchOWAForceSaveFileTypes")]
            ATT_MS_EXCH_OWA_FORCE_SAVE_FILE_TYPES = 1030522395,

            [Description("msExchOWAForceSaveMIMETypes")]
            ATT_MS_EXCH_OWA_FORCE_SAVE_MIME_TYPES = 1030522396,

            [Description("msExchOWABlockedFileTypes")]
            ATT_MS_EXCH_OWA_BLOCKED_FILE_TYPES = 1030522397,

            [Description("msExchOWABlockedMIMETypes")]
            ATT_MS_EXCH_OWA_BLOCKED_MIME_TYPES = 1030522398,

            [Description("msExchOWARemoteDocumentsAllowedServers")]
            ATT_MS_EXCH_OWA_REMOTE_DOCUMENTS_ALLOWED_SERVERS = 1030522399,

            [Description("msExchOWARemoteDocumentsBlockedServers")]
            ATT_MS_EXCH_OWA_REMOTE_DOCUMENTS_BLOCKED_SERVERS = 1030522400,

            [Description("msExchOWARemoteDocumentsInternalDomainSuffixList")]
            ATT_MS_EXCH_OWA_REMOTE_DOCUMENTS_INTERNAL_DOMAIN_SUFFIX_LIST = 1030522401,

            [Description("msExchUMDialPlanDefaultAutoAttendantLink")]
            ATT_MS_EXCH_UM_DIAL_PLAN_DEFAULT_AUTO_ATTENDANT_LINK = 1030522128,

            [Description("msExchUMDialPlanDefaultAutoAttendantBL")]
            ATT_MS_EXCH_UM_DIAL_PLAN_DEFAULT_AUTO_ATTENDANT_BL = 1030522129,

            [Description("msExchUMHuntGroupDialPlanLink")]
            ATT_MS_EXCH_UM_HUNT_GROUP_DIAL_PLAN_LINK = 1030522134,

            [Description("msExchUMHuntGroupDialPlanBL")]
            ATT_MS_EXCH_UM_HUNT_GROUP_DIAL_PLAN_BL = 1030522135,

            [Description("msExchELCExpiryDestinationLink")]
            ATT_MS_EXCH_ELC_EXPIRY_DESTINATION_LINK = 1030522139,

            [Description("msExchAttachmentFilteringExceptionConnectorsLink")]
            ATT_MS_EXCH_ATTACHMENT_FILTERING_EXCEPTION_CONNECTORS_LINK = 1030522158,

            [Description("msExchJournalingRulesLink")]
            ATT_MS_EXCH_JOURNALING_RULES_LINK = 1030522163,

            [Description("msExchMailboxOABVirtualDirectoriesLink")]
            ATT_MS_EXCH_MAILBOX_OAB_VIRTUAL_DIRECTORIES_LINK = 1030522191,

            [Description("msExchMailboxOABVirtualDirectoriesBL")]
            ATT_MS_EXCH_MAILBOX_OAB_VIRTUAL_DIRECTORIES_BL = 1030522192,

            [Description("msExchOABVirtualDirectoriesLink")]
            ATT_MS_EXCH_OAB_VIRTUAL_DIRECTORIES_LINK = 1030522193,

            [Description("msExchOABVirtualDirectoriesBL")]
            ATT_MS_EXCH_OAB_VIRTUAL_DIRECTORIES_BL = 1030522194,

            [Description("msExchELCAutoCopyAddressLink")]
            ATT_MS_EXCH_ELC_AUTO_COPY_ADDRESS_LINK = 1030522195,

            [Description("msExchUMMailboxPolicyDialPlanLink")]
            ATT_MS_EXCH_UM_MAILBOX_POLICY_DIAL_PLAN_LINK = 1030522206,

            [Description("msExchUMMailboxPolicyDialPlanBL")]
            ATT_MS_EXCH_UM_MAILBOX_POLICY_DIAL_PLAN_BL = 1030522207,

            [Description("msExchSmtpSendReceiveConnectorLink")]
            ATT_MS_EXCH_SMTP_SEND_RECEIVE_CONNECTOR_LINK = 1030522218,

            [Description("msExchTransportSubmissionServerOverrideList")]
            ATT_MS_EXCH_TRANSPORT_SUBMISSION_SERVER_OVERRIDE_LIST = 1030522315,

            [Description("msExchServerAdminDelegationLink")]
            ATT_MS_EXCH_SERVER_ADMIN_DELEGATION_LINK = 1030522319,

            [Description("msExchServerAdminDelegationBL")]
            ATT_MS_EXCH_SERVER_ADMIN_DELEGATION_BL = 1030522320,

            [Description("homePostalAddress")]
            ATT_ADDRESS_HOME = 131689,

            [Description("msDS-PhoneticCompanyName")]
            ATT_MS_DS_PHONETIC_COMPANY_NAME = 591769,

            [Description("msDS-PhoneticDepartment")]
            ATT_MS_DS_PHONETIC_DEPARTMENT = 591768,

            [Description("msDS-PhoneticFirstName")]
            ATT_MS_DS_PHONETIC_FIRST_NAME = 591766,

            [Description("msDS-PhoneticLastName")]
            ATT_MS_DS_PHONETIC_LAST_NAME = 591767,

            [Description("msExchAssistantName")]
            ATT_MS_EXCH_ASSISTANT_NAME = 131516,

            [Description("telephoneAssistant")]
            ATT_MS_EXCH_TELEPHONE_ASSISTANT = 131151,

            [Description("msExchELCExpiryAction")]
            ATT_MS_EXCH_ELC_EXPIRY_ACTION = 1030522040,

            [Description("msExchELCFolderName")]
            ATT_MS_EXCH_ELC_FOLDER_NAME = 1030522034,

            [Description("msExchUMMaxGreetingDuration")]
            ATT_MS_EXCH_UM_MAX_GREETING_DURATION = 1030522017,

            [Description("msExchUMPinPolicyExpiryDays")]
            ATT_MS_EXCH_UM_PIN_POLICY_EXPIRY_DAYS = 1030522026,

            [Description("msExchAcceptedDomainFlags")]
            ATT_MS_EXCH_ACCEPTED_DOMAIN_FLAGS = 1030522425,

            [Description("msExchAcceptedDomainName")]
            ATT_MS_EXCH_ACCEPTED_DOMAIN_NAME = 1030522458,

            [Description("msExchAttachmentFilteringAdminMessage")]
            ATT_MS_EXCH_ATTACHMENT_FILTERING_ADMIN_MESSAGE = 1030522534,

            [Description("msExchAvailabilityForeignConnectorDomain")]
            ATT_MS_EXCH_AVAILABILITY_FOREIGN_CONNECTOR_DOMAIN = 1030522520,

            [Description("msExchAvailabilityForeignConnectorType")]
            ATT_MS_EXCH_AVAILABILITY_FOREIGN_CONNECTOR_TYPE = 1030522519,

            [Description("msExchCost")]
            ATT_MS_EXCH_COST = 1030522532,

            [Description("msExchDomainContentConfigFlags")]
            ATT_MS_EXCH_DOMAIN_CONTENT_CONFIG_FLAGS = 1030522416,

            [Description("msExchEdgeSyncCredential")]
            ATT_MS_EXCH_EDGE_SYNC_CREDENTIAL = 1030522412,

            [Description("msExchEdgeSyncLease")]
            ATT_MS_EXCH_EDGE_SYNC_LEASE = 1030522414,

            [Description("msExchEdgeSyncStatus")]
            ATT_MS_EXCH_EDGE_SYNC_STATUS = 1030522415,

            [Description("msExchELCAdminDescriptionLocalized")]
            ATT_MS_EXCH_ELC_ADMIN_DESCRIPTION_LOCALIZED = 1030522432,

            [Description("msExchELCAuditLogDirectorySizeLimit")]
            ATT_MS_EXCH_ELC_AUDIT_LOG_DIRECTORY_SIZE_LIMIT = 1030522493,

            [Description("msExchELCAuditLogFileAgeLimit")]
            ATT_MS_EXCH_ELC_AUDIT_LOG_FILE_AGE_LIMIT = 1030522495,

            [Description("msExchELCAuditLogFileSizeLimit")]
            ATT_MS_EXCH_ELC_AUDIT_LOG_FILE_SIZE_LIMIT = 1030522494,

            [Description("msExchELCAuditLogPath")]
            ATT_MS_EXCH_ELC_AUDIT_LOG_PATH = 1030522492,

            [Description("msExchELCExpirySuspensionEnd")]
            ATT_MS_EXCH_ELC_EXPIRY_SUSPENSION_END = 1030522443,

            [Description("msExchELCExpirySuspensionStart")]
            ATT_MS_EXCH_ELC_EXPIRY_SUSPENSION_START = 1030522442,

            [Description("msExchELCFolderNameLocalized")]
            ATT_MS_EXCH_ELC_FOLDER_NAME_LOCALIZED = 1030522433,

            [Description("msExchELCMailboxFlags")]
            ATT_MS_EXCH_ELC_MAILBOX_FLAGS = 1030522441,

            [Description("msExchELCOrganizationalRootURL")]
            ATT_MS_EXCH_ELC_ORGANIZATIONAL_ROOT_URL = 1030522514,

            [Description("msExchEncryptedTLSP12")]
            ATT_MS_EXCH_ENCRYPTED_TLS_P12 = 1030522434,

            [Description("msExchEncryptedTransportServiceKPK")]
            ATT_MS_EXCH_ENCRYPTED_TRANSPORT_SERVICE_KPK = 1030522468,

            [Description("msExchForeignForestOrgAdminUSGSid")]
            ATT_MS_EXCH_FOREIGN_FOREST_ORG_ADMIN_USG_SID = 1030522525,

            [Description("msExchForeignForestReadOnlyAdminUSGSid")]
            ATT_MS_EXCH_FOREIGN_FOREST_READ_ONLY_ADMIN_USG_SID = 1030522527,

            [Description("msExchForeignForestRecipientAdminUSGSid")]
            ATT_MS_EXCH_FOREIGN_FOREST_RECIPIENT_ADMIN_USG_SID = 1030522526,

            [Description("msExchForeignForestServerAdminUSGSid")]
            ATT_MS_EXCH_FOREIGN_FOREST_SERVER_ADMIN_USG_SID = 1030522528,

            [Description("msExchInternalSMTPServers")]
            ATT_MS_EXCH_INTERNAL_SMTP_SERVERS = 1030522469,

            [Description("msExchLastAppliedRecipientFilter")]
            ATT_MS_EXCH_LAST_APPLIED_RECIPIENT_FILTER = 1030522509,

            [Description("msExchMailGatewayFlags")]
            ATT_MS_EXCH_MAIL_GATEWAY_FLAGS = 1030522467,

            [Description("msExchMailboxRoleFlags")]
            ATT_MS_EXCH_MAILBOX_ROLE_FLAGS = 1030522457,

            [Description("msExchMasterAccountHistory")]
            ATT_MS_EXCH_MASTER_ACCOUNT_HISTORY = 1030522515,

            [Description("msExchMaxDumpsterSizePerStorageGroup")]
            ATT_MS_EXCH_MAX_DUMPSTER_SIZE_PER_STORAGE_GROUP = 1030522408,

            [Description("msExchMaxDumpsterTime")]
            ATT_MS_EXCH_MAX_DUMPSTER_TIME = 1030522409,

            [Description("msExchMessageHygieneBypassedSenderDomains")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BYPASSED_SENDER_DOMAINS = 1030522516,

            [Description("msExchMessageHygieneBypassedSenders")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_BYPASSED_SENDERS = 1030522462,

            [Description("msExchMessageHygieneMachineGeneratedRejectionResponse")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_MACHINE_GENERATED_REJECTION_RESPONSE = 1030522545,

            [Description("msExchMessageHygieneQuarantineMailbox")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_QUARANTINE_MAILBOX = 1030522440,

            [Description("msExchMessageHygieneSCLJunkThreshold")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_SCL_JUNK_THRESHOLD = 1030522463,

            [Description("msExchMessageHygieneStaticEntryRejectionResponse")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_STATIC_ENTRY_REJECTION_RESPONSE = 1030522546,

            [Description("msExchMLSDomainGatewaySMTPAddress")]
            ATT_MS_EXCH_MLS_DOMAIN_GATEWAY_SMTP_ADDRESS = 1030522417,

            [Description("msExchMLSEncryptedDecryptionP12Current")]
            ATT_MS_EXCH_MLS_ENCRYPTED_DECRYPTION_P12_CURRENT = 1030522447,

            [Description("msExchMLSEncryptedDecryptionP12Previous")]
            ATT_MS_EXCH_MLS_ENCRYPTED_DECRYPTION_P12_PREVIOUS = 1030522428,

            [Description("msExchMLSEncryptedRecoveryP12Current")]
            ATT_MS_EXCH_MLS_ENCRYPTED_RECOVERY_P12_CURRENT = 1030522449,

            [Description("msExchMLSEncryptedRecoveryP12Previous")]
            ATT_MS_EXCH_MLS_ENCRYPTED_RECOVERY_P12_PREVIOUS = 1030522430,

            [Description("msExchMLSEncryptedSigningP12Current")]
            ATT_MS_EXCH_MLS_ENCRYPTED_SIGNING_P12_CURRENT = 1030522448,

            [Description("msExchMLSEncryptedSigningP12Previous")]
            ATT_MS_EXCH_MLS_ENCRYPTED_SIGNING_P12_PREVIOUS = 1030522429,

            [Description("msExchMobileDeviceNumberOfPreviousPasswordsDisallowed")]
            ATT_MS_EXCH_MOBILE_DEVICE_NUMBER_OF_PREVIOUS_PASSWORDS_DISALLOWED = 1030522474,

            [Description("msExchMobileDevicePasswordExpiration")]
            ATT_MS_EXCH_MOBILE_DEVICE_PASSWORD_EXPIRATION = 1030522475,

            [Description("msExchMobileMailboxFlags")]
            ATT_MS_EXCH_MOBILE_MAILBOX_FLAGS = 1030522538,

            [Description("msExchMobileOutboundCharset")]
            ATT_MS_EXCH_MOBILE_OUTBOUND_CHARSET = 1030522473,

            [Description("msExchMobilePolicySalt")]
            ATT_MS_EXCH_MOBILE_POLICY_SALT = 1030522547,

            [Description("msExchMSMCertPolicyOid")]
            ATT_MS_EXCH_MSM_CERT_POLICY_OID = 1030522450,

            [Description("msExchOWATranscodingFlags")]
            ATT_MS_EXCH_OWA_TRANSCODING_FLAGS = 1030522452,

            [Description("msExchPermittedAuthN")]
            ATT_MS_EXCH_PERMITTED_AUTHN = 1030522420,

            [Description("msExchPhoneticSupport")]
            ATT_MS_EXCH_PHONETIC_SUPPORT = 1030522537,

            [Description("msExchPopImapBanner")]
            ATT_MS_EXCH_POP_IMAP_BANNER = 1030522502,

            [Description("msExchPopImapCalendarItemRetrievalOption")]
            ATT_MS_EXCH_POP_IMAP_CALENDAR_ITEM_RETRIEVAL_OPTION = 1030522501,

            [Description("msExchPopImapCommandSize")]
            ATT_MS_EXCH_POP_IMAP_COMMAND_SIZE = 1030522497,

            [Description("msExchPopImapFlags")]
            ATT_MS_EXCH_POP_IMAP_FLAGS = 1030522500,

            [Description("msExchPopImapIncomingPreauthConnectionTimeout")]
            ATT_MS_EXCH_POP_IMAP_INCOMING_PREAUTH_CONNECTION_TIMEOUT = 1030522496,

            [Description("msExchPopImapMaxIncomingConnectionFromSingleSource")]
            ATT_MS_EXCH_POP_IMAP_MAX_INCOMING_CONNECTION_FROM_SINGLE_SOURCE = 1030522498,

            [Description("msExchPopImapMaxIncomingConnectionPerUser")]
            ATT_MS_EXCH_POP_IMAP_MAX_INCOMING_CONNECTION_PER_USER = 1030522499,

            [Description("msExchPopImapX509CertificateName")]
            ATT_MS_EXCH_POP_IMAP_X509_CERTIFICATE_NAME = 1030522491,

            [Description("msExchProductID")]
            ATT_MS_EXCH_PRODUCT_ID = 1030522544,

            [Description("msExchPromptPublishingPoint")]
            ATT_MS_EXCH_PROMPT_PUBLISHING_POINT = 1030522522,

            [Description("msExchReceiveHashedPassword")]
            ATT_MS_EXCH_RECEIVE_HASHED_PASSWORD = 1030522422,

            [Description("msExchReceiveUserName")]
            ATT_MS_EXCH_RECEIVE_USER_NAME = 1030522421,

            [Description("msExchRecipientDisplayType")]
            ATT_MS_EXCH_RECIPIENT_DISPLAY_TYPE = 1030522410,

            [Description("msExchRecipientFilterFlags")]
            ATT_MS_EXCH_RECIPIENT_FILTER_FLAGS = 1030522510,

            [Description("msExchRecipientTypeDetails")]
            ATT_MS_EXCH_RECIPIENT_TYPE_DETAILS = 1030522535,

            [Description("msExchRMSTemplatePath")]
            ATT_MS_EXCH_RMS_TEMPLATE_PATH = 1030522488,

            [Description("msExchRpcHttpFlags")]
            ATT_MS_EXCH_RPC_HTTP_FLAGS = 1030522464,

            [Description("msExchSendEncryptedPassword")]
            ATT_MS_EXCH_SEND_ENCRYPTED_PASSWORD = 1030522424,

            [Description("msExchSendUserName")]
            ATT_MS_EXCH_SEND_USER_NAME = 1030522423,

            [Description("msExchServerEKPKPublicKey")]
            ATT_MS_EXCH_SERVER_EKPK_PUBLIC_KEY = 1030522437,

            [Description("msExchServerEncryptedKPK")]
            ATT_MS_EXCH_SERVER_ENCRYPTED_KPK = 1030522435,

            [Description("msExchServerInternalTLSCert")]
            ATT_MS_EXCH_SERVER_INTERNAL_TLS_CERT = 1030522438,

            [Description("msExchSmtpReceiveConnectionInactivityTimeout")]
            ATT_MS_EXCH_SMTP_RECEIVE_CONNECTION_INACTIVITY_TIMEOUT = 1030522548,

            [Description("msExchSMTPReceiveConnectorFQDN")]
            ATT_MS_EXCH_SMTP_RECEIVE_CONNECTOR_FQDN = 1030522483,

            [Description("msExchSMTPReceiveExternallySecuredAs")]
            ATT_MS_EXCH_SMTP_RECEIVE_EXTERNALLY_SECURED_AS = 1030522482,

            [Description("msExchSMTPReceiveInboundSecurityFlag")]
            ATT_MS_EXCH_SMTP_RECEIVE_INBOUND_SECURITY_FLAG = 1030522487,

            [Description("msExchSMTPReceiveMaxInboundConnectionsPercPerSource")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_INBOUND_CONNECTIONS_PERC_PER_SOURCE = 1030522486,

            [Description("msExchSMTPReceivePostmasterAddress")]
            ATT_MS_EXCH_SMTP_RECEIVE_POSTMASTER_ADDRESS = 1030522485,

            [Description("msExchSMTPSendConnectorFQDN")]
            ATT_MS_EXCH_SMTP_SEND_CONNECTOR_FQDN = 1030522511,

            [Description("msExchSMTPSendExternallySecuredAs")]
            ATT_MS_EXCH_SMTP_SEND_EXTERNALLY_SECURED_AS = 1030522512,

            [Description("msExchTlsAlternateSubject")]
            ATT_MS_EXCH_TLS_ALTERNATE_SUBJECT = 1030522529,

            [Description("msExchTransportConnectivityLogDirectorySize")]
            ATT_MS_EXCH_TRANSPORT_CONNECTIVITY_LOG_DIRECTORY_SIZE = 1030522480,

            [Description("msExchTransportConnectivityLogFileSize")]
            ATT_MS_EXCH_TRANSPORT_CONNECTIVITY_LOG_FILE_SIZE = 1030522481,

            [Description("msExchTransportConnectivityLogPath")]
            ATT_MS_EXCH_TRANSPORT_CONNECTIVITY_LOG_PATH = 1030522479,

            [Description("msExchTransportDropDirectoryName")]
            ATT_MS_EXCH_TRANSPORT_DROP_DIRECTORY_NAME = 1030522466,

            [Description("msExchTransportDropDirectoryQuota")]
            ATT_MS_EXCH_TRANSPORT_DROP_DIRECTORY_QUOTA = 1030522513,

            [Description("msExchTransportMaxConcurrentMailboxSubmissions")]
            ATT_MS_EXCH_TRANSPORT_MAX_CONCURRENT_MAILBOX_SUBMISSIONS = 1030522536,

            [Description("msExchTransportMaxConnectivityLogAge")]
            ATT_MS_EXCH_TRANSPORT_MAX_CONNECTIVITY_LOG_AGE = 1030522478,

            [Description("msExchTransportMaxPickupDirectoryMessagesPerMinute")]
            ATT_MS_EXCH_TRANSPORT_MAX_PICKUP_DIRECTORY_MESSAGES_PER_MINUTE = 1030522477,

            [Description("msExchTransportPipelineTracingPath")]
            ATT_MS_EXCH_TRANSPORT_PIPELINE_TRACING_PATH = 1030522539,

            [Description("msExchTransportPipelineTracingSenderAddress")]
            ATT_MS_EXCH_TRANSPORT_PIPELINE_TRACING_SENDER_ADDRESS = 1030522540,

            [Description("msExchTransportReplayDirectoryPath")]
            ATT_MS_EXCH_TRANSPORT_REPLAY_DIRECTORY_PATH = 1030522476,

            [Description("msExchTransportRootDropDirectoryPath")]
            ATT_MS_EXCH_TRANSPORT_ROOT_DROP_DIRECTORY_PATH = 1030522465,

            [Description("msExchTransportRoutingLogMaxAge")]
            ATT_MS_EXCH_TRANSPORT_ROUTING_LOG_MAX_AGE = 1030522543,

            [Description("msExchTransportRoutingLogMaxDirectorySize")]
            ATT_MS_EXCH_TRANSPORT_ROUTING_LOG_MAX_DIRECTORY_SIZE = 1030522542,

            [Description("msExchTransportRoutingLogPath")]
            ATT_MS_EXCH_TRANSPORT_ROUTING_LOG_PATH = 1030522541,

            [Description("msExchTransportSettingsFlags")]
            ATT_MS_EXCH_TRANSPORT_SETTINGS_FLAGS = 1030522531,

            [Description("msExchTransportSiteFlags")]
            ATT_MS_EXCH_TRANSPORT_SITE_FLAGS = 1030522436,

            [Description("msExchUMDialPlanFlags")]
            ATT_MS_EXCH_UM_DIAL_PLAN_FLAGS = 1030522523,

            [Description("msExchUMDialPlanURIType")]
            ATT_MS_EXCH_UM_DIAL_PLAN_URI_TYPE = 1030522456,

            [Description("msExchUMDialPlanVoipSecurity")]
            ATT_MS_EXCH_UM_DIAL_PLAN_VOIP_SECURITY = 1030522518,

            [Description("msExchUMIPGatewayFlags")]
            ATT_MS_EXCH_UM_IP_GATEWAY_FLAGS = 1030522454,

            [Description("msExchUMIPGatewayPort")]
            ATT_MS_EXCH_UM_IP_GATEWAY_PORT = 1030522455,

            [Description("msExchUMQueryBaseDN")]
            ATT_MS_EXCH_UM_QUERY_BASE_DN = 1030522521,

            [Description("msExchUMServerWritableFlags")]
            ATT_MS_EXCH_UM_SERVER_WRITABLE_FLAGS = 1030522530,

            [Description("msExchUserCulture")]
            ATT_MS_EXCH_USER_CULTURE = 1030522453,

            [Description("msExchOWATranscodingMimeTypes")]
            ATT_MS_EXCH_OWA_TRANSCODING_MIME_TYPES = 1030522451,

            [Description("msExchSMTPReceiveDefaultAcceptedDomainLink")]
            ATT_MS_EXCH_SMTP_RECEIVE_DEFAULT_ACCEPTED_DOMAIN_LINK = 1030522484,

            [Description("msExchMobileRemoteDocumentsAllowedServers")]
            ATT_MS_EXCH_MOBILE_REMOTE_DOCUMENTS_ALLOWED_SERVERS = 1030522470,

            [Description("msExchMobileRemoteDocumentsBlockedServers")]
            ATT_MS_EXCH_MOBILE_REMOTE_DOCUMENTS_BLOCKED_SERVERS = 1030522471,

            [Description("msExchMobileRemoteDocumentsInternalDomainSuffixList")]
            ATT_MS_EXCH_MOBILE_REMOTE_DOCUMENTS_INTERNAL_DOMAIN_SUFFIX_LIST = 1030522472,

            [Description("msExchServerSite")]
            ATT_MS_EXCH_SERVER_SITE = 1030522517,

            [Description("msExchVersion")]
            ATT_MS_EXCH_VERSION = 1030522533,

            [Description("contentType")]
            ATT_MS_EXCH_CONTENT_TYPE = 131553,

            [Description("msExchMessageClassificationBanner")]
            ATT_MS_EXCH_MESSAGE_CLASSIFICATION_BANNER = 1030522328,

            [Description("oWAServer")]
            ATT_MS_EXCH_OWA_SERVER = 131680,

            [Description("msExchUMPilotIdentifier")]
            ATT_MS_EXCH_UM_PILOT_IDENTIFIER = 1030522133,

            [Description("msExchMessageHygieneFlags")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_FLAGS = 1030522367,

            [Description("msExchMessageHygieneSCLDeleteThreshold")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_SCL_DELETE_THRESHOLD = 1030522459,

            [Description("msExchMessageHygieneSCLQuarantineThreshold")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_SCL_QUARANTINE_THRESHOLD = 1030522461,

            [Description("msExchMessageHygieneSCLRejectThreshold")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_SCL_REJECT_THRESHOLD = 1030522460,

            [Description("msExchSafeRecipientsHash")]
            ATT_MS_EXCH_SAFE_RECIPIENTS_HASH = 1030522446,

            [Description("msExchSafeSendersHash")]
            ATT_MS_EXCH_SAFE_SENDERS_HASH = 1030522445,

            [Description("msExchUMPinChecksum")]
            ATT_MS_EXCH_UM_PIN_CHECKSUM = 1030522024,

            [Description("msExchResourceSearchProperties")]
            ATT_MS_EXCH_RESOURCE_SEARCH_PROPERTIES = 1030522011,

            [Description("msExchEdgeSyncAdamLdapPort")]
            ATT_MS_EXCH_EDGE_SYNC_ADAM_LDAP_PORT = 1030522554,

            [Description("msExchEdgeSyncAdamSSLPort")]
            ATT_MS_EXCH_EDGE_SYNC_ADAM_SSL_PORT = 1030522553,

            [Description("msExchMaxBlockedSenders")]
            ATT_MS_EXCH_MAX_BLOCKED_SENDERS = 1030522558,

            [Description("msExchMaxSafeSenders")]
            ATT_MS_EXCH_MAX_SAFE_SENDERS = 1030522557,

            [Description("msExchOABTTL")]
            ATT_MS_EXCH_OAB_TTL = 1030522552,

            [Description("msExchQueryFilterMetadata")]
            ATT_MS_EXCH_QUERY_FILTER_METADATA = 1030522555,

            [Description("msExchSmtpReceiveMaxConnectionRatePerMinute")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_CONNECTION_RATE_PER_MINUTE = 1030522549,

            [Description("msExchTLSReceiveDomainSecureList")]
            ATT_MS_EXCH_TLS_RECEIVE_DOMAIN_SECURE_LIST = 1030522550,

            [Description("msExchTLSSendDomainSecureList")]
            ATT_MS_EXCH_TLS_SEND_DOMAIN_SECURE_LIST = 1030522551,

            [Description("msExchTransportExternalIPAddress")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_IP_ADDRESS = 1030522556,

            [Description("msExchTransportExternalTrustedServers")]
            ATT_MS_EXCH_TRANSPORT_EXTERNAL_TRUSTED_SERVERS = 1030522560,

            [Description("msExchUMSpeechGrammarFilterList")]
            ATT_MS_EXCH_UM_SPEECH_GRAMMAR_FILTER_LIST = 1030522559,

            [Description("msExchPoliciesExcluded")]
            ATT_MS_EXCH_POLICIES_EXCLUDED = 1030521731,

            [Description("msExchPoliciesIncluded")]
            ATT_MS_EXCH_POLICIES_INCLUDED = 1030521730,

            [Description("msExchUMAudioCodec")]
            ATT_MS_EXCH_UM_AUDIO_CODEC = 1030522058,

            [Description("msExchDSNText")]
            ATT_MS_EXCH_DSN_TEXT = 1030522280,

            [Description("msExchForeignForestFQDN")]
            ATT_MS_EXCH_FOREIGN_FOREST_FQDN = 1030522524,

            [Description("msExchUMAvailableLanguages")]
            ATT_MS_EXCH_UM_AVAILABLE_LANGUAGES = 1030522059,

            [Description("msExchUMAvailableTTSLanguages")]
            ATT_MS_EXCH_UM_AVAILABLE_TTS_LANGUAGES = 1030522061,

            [Description("msExchUMDefaultLanguage")]
            ATT_MS_EXCH_UM_DEFAULT_LANGUAGE = 1030522060,

            [Description("msExchUMDefaultTTSLanguage")]
            ATT_MS_EXCH_UM_DEFAULT_TTS_LANGUAGE = 1030522062,

            [Description("msExchPurportedSearchUI")]
            ATT_MS_EXCH_PURPORTED_SEARCH_UI = 1736704066,

            [Description("company")]
            ATT_COMPANY = 131218,

            [Description("department")]
            ATT_DEPARTMENT = 131213,

            [Description("extensionAttribute1")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_1 = 131495,

            [Description("extensionAttribute10")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_10 = 131504,

            [Description("extensionAttribute11")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_11 = 131671,

            [Description("extensionAttribute12")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_12 = 131672,

            [Description("extensionAttribute13")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_13 = 131673,

            [Description("extensionAttribute14")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_14 = 131674,

            [Description("extensionAttribute15")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_15 = 131675,

            [Description("extensionAttribute2")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_2 = 131496,

            [Description("extensionAttribute3")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_3 = 131497,

            [Description("extensionAttribute4")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_4 = 131498,

            [Description("extensionAttribute5")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_5 = 131499,

            [Description("extensionAttribute6")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_6 = 131500,

            [Description("extensionAttribute7")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_7 = 131501,

            [Description("extensionAttribute8")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_8 = 131502,

            [Description("extensionAttribute9")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_9 = 131503,

            [Description("msExchResourcePropertySchemaObsolete")]
            ATT_MS_EXCH_RESOURCE_PROPERTY_SCHEMA_OBSOLETE = 1030522009,

            [Description("msExchResourcePropertySchema")]
            ATT_MS_EXCH_RESOURCE_PROPERTY_SCHEMA = 1030522561,

            [Description("msExchForeignForestPublicFolderAdminUSGSid")]
            ATT_MS_EXCH_FOREIGN_FOREST_PUBLIC_FOLDER_ADMIN_USG_SID = 1030522577,

            [Description("msExchInternalNLBBypassHostName")]
            ATT_MS_EXCH_INTERNAL_NLB_BYPASS_HOST_NAME = 1030522562,

            [Description("msExchMobileAdditionalFlags")]
            ATT_MS_EXCH_MOBILE_ADDITIONAL_FLAGS = 1030522563,

            [Description("msExchMobileAllowBluetooth")]
            ATT_MS_EXCH_MOBILE_ALLOW_BLUETOOTH = 1030522566,

            [Description("msExchMobileAllowSMIMEEncryptionAlgorithmNegotiation")]
            ATT_MS_EXCH_MOBILE_ALLOW_SMIME_ENCRYPTION_ALGORITHM_NEGOTIATION = 1030522571,

            [Description("msExchMobileApprovedApplicationList")]
            ATT_MS_EXCH_MOBILE_APPROVED_APPLICATION_LIST = 1030522573,

            [Description("msExchMobileMaxCalendarAgeFilter")]
            ATT_MS_EXCH_MOBILE_MAX_CALENDAR_AGE_FILTER = 1030522567,

            [Description("msExchMobileMaxEmailAgeFilter")]
            ATT_MS_EXCH_MOBILE_MAX_EMAIL_AGE_FILTER = 1030522568,

            [Description("msExchMobileMaxEmailBodyTruncationSize")]
            ATT_MS_EXCH_MOBILE_MAX_EMAIL_BODY_TRUNCATION_SIZE = 1030522564,

            [Description("msExchMobileMaxEmailHTMLBodyTruncationSize")]
            ATT_MS_EXCH_MOBILE_MAX_EMAIL_HTML_BODY_TRUNCATION_SIZE = 1030522565,

            [Description("msExchMobileMinDevicePasswordComplexCharacters")]
            ATT_MS_EXCH_MOBILE_MIN_DEVICE_PASSWORD_COMPLEX_CHARACTERS = 1030522575,

            [Description("msExchMobileRequireEncryptionSMIMEAlgorithm")]
            ATT_MS_EXCH_MOBILE_REQUIRE_ENCRYPTION_SMIME_ALGORITHM = 1030522570,

            [Description("msExchMobileRequireSignedSMIMEAlgorithm")]
            ATT_MS_EXCH_MOBILE_REQUIRE_SIGNED_SMIME_ALGORITHM = 1030522569,

            [Description("msExchMobileUnapprovedInROMApplicationList")]
            ATT_MS_EXCH_MOBILE_UNAPPROVED_IN_ROM_APPLICATION_LIST = 1030522572,

            [Description("msExchStandbyCopyMachines")]
            ATT_MS_EXCH_STANDBY_COPY_MACHINES = 1030522574,

            [Description("msExchSchemaVersionPt")]
            ATT_MS_EXCH_SCHEMA_VERSION_PT = 1736704097,

            [Description("msRTCSIP-PrimaryUserAddress")]
            ATT_MS_RTC_SIP_PRIMARYUSERADDRESS = 2122776577,

            [Description("msRTCSIP-UserEnabled")]
            ATT_MS_RTC_SIP_USERENABLED = 2122776582,

            [Description("msRTCSIP-PrimaryHomeServer")]
            ATT_MS_RTC_SIP_PRIMARYHOMESERVER = 2122776633,

            [Description("msRTCSIP-TargetHomeServer")]
            ATT_MS_RTC_SIP_TARGETHOMESERVER = 2122776623,

            [Description("msRTCSIP-FederationEnabled")]
            ATT_MS_RTC_SIP_FEDERATIONENABLED = 2122776643,

            [Description("msRTCSIP-InternetAccessEnabled")]
            ATT_MS_RTC_SIP_INTERNETACCESSENABLED = 2122776644,

            [Description("msRTCSIP-EnterpriseServices")]
            ATT_MS_RTC_SIP_ENTERPRISESERVICES = 2122776595,

            [Description("msRTCSIP-PoolAddress")]
            ATT_MS_RTC_SIP_POOLADDRESS = 2122776655,

            [Description("msRTCSIP-ServerData")]
            ATT_MS_RTC_SIP_SERVERDATA = 2122776636,

            [Description("msRTCSIP-ServerVersion")]
            ATT_MS_RTC_SIP_SERVERVERSION = 2122776682,

            [Description("msRTCSIP-MaxNumSubscriptionsPerUser")]
            ATT_MS_RTC_SIP_MAXNUMSUBSCRIPTIONSPERUSER = 2122776629,

            [Description("msRTCSIP-MinRegistrationTimeout")]
            ATT_MS_RTC_SIP_MINREGISTRATIONTIMEOUT = 2122776596,

            [Description("msRTCSIP-DefRegistrationTimeout")]
            ATT_MS_RTC_SIP_DEFREGISTRATIONTIMEOUT = 2122776597,

            [Description("msRTCSIP-MaxRegistrationTimeout")]
            ATT_MS_RTC_SIP_MAXREGISTRATIONTIMEOUT = 2122776598,

            [Description("msRTCSIP-MinPresenceSubscriptionTimeout")]
            ATT_MS_RTC_SIP_MINPRESENCESUBSCRIPTIONTIMEOUT = 2122776599,

            [Description("msRTCSIP-DefPresenceSubscriptionTimeout")]
            ATT_MS_RTC_SIP_DEFPRESENCESUBSCRIPTIONTIMEOUT = 2122776600,

            [Description("msRTCSIP-MaxPresenceSubscriptionTimeout")]
            ATT_MS_RTC_SIP_MAXPRESENCESUBSCRIPTIONTIMEOUT = 2122776601,

            [Description("msRTCSIP-MinRoamingDataSubscriptionTimeout")]
            ATT_MS_RTC_SIP_MINROAMINGDATASUBSCRIPTIONTIMEOUT = 2122776602,

            [Description("msRTCSIP-DefRoamingDataSubscriptionTimeout")]
            ATT_MS_RTC_SIP_DEFROAMINGDATASUBSCRIPTIONTIMEOUT = 2122776603,

            [Description("msRTCSIP-MaxRoamingDataSubscriptionTimeout")]
            ATT_MS_RTC_SIP_MAXROAMINGDATASUBSCRIPTIONTIMEOUT = 2122776604,

            [Description("msRTCSIP-NumDevicesPerUser")]
            ATT_MS_RTC_SIP_NUMDEVICESPERUSER = 2122776624,

            [Description("msRTCSIP-EnableBestEffortNotify")]
            ATT_MS_RTC_SIP_ENABLEBESTEFFORTNOTIFY = 2122776648,

            [Description("msRTCSIP-UserDomainList")]
            ATT_MS_RTC_SIP_USERDOMAINLIST = 2122776649,

            [Description("msRTCSIP-GlobalSettingsData")]
            ATT_MS_RTC_SIP_GLOBALSETTINGSDATA = 2122776634,

            [Description("msRTCSIP-DefaultRouteToEdgeProxy")]
            ATT_MS_RTC_SIP_DEFAULTROUTETOEDGEPROXY = 2122776645,

            [Description("msRTCSIP-DefaultRouteToEdgeProxyPort")]
            ATT_MS_RTC_SIP_DEFAULTROUTETOEDGEPROXYPORT = 2122776646,

            [Description("msRTCSIP-EnableFederation")]
            ATT_MS_RTC_SIP_ENABLEFEDERATION = 2122776647,

            [Description("msRTCSIP-SearchMaxResults")]
            ATT_MS_RTC_SIP_SEARCHMAXRESULTS = 2122776606,

            [Description("msRTCSIP-SearchMaxRequests")]
            ATT_MS_RTC_SIP_SEARCHMAXREQUESTS = 2122776621,

            [Description("msRTCSIP-MaxNumOutstandingSearchPerServer")]
            ATT_MS_RTC_SIP_MAXNUMOUTSTANDINGSEARCHPERSERVER = 2122776628,

            [Description("msRTCSIP-DomainName")]
            ATT_MS_RTC_SIP_DOMAINNAME = 2122776609,

            [Description("msRTCSIP-DomainData")]
            ATT_MS_RTC_SIP_DOMAINDATA = 2122776637,

            [Description("msRTCSIP-TrustedServerData")]
            ATT_MS_RTC_SIP_TRUSTEDSERVERDATA = 2122776638,

            [Description("msRTCSIP-BackEndServer")]
            ATT_MS_RTC_SIP_BACKENDSERVER = 2122776640,

            [Description("msRTCSIP-PoolType")]
            ATT_MS_RTC_SIP_POOLTYPE = 2122776641,

            [Description("msRTCSIP-PoolDisplayName")]
            ATT_MS_RTC_SIP_POOLDISPLAYNAME = 2122776650,

            [Description("msRTCSIP-FrontEndServers")]
            ATT_MS_RTC_SIP_FRONTENDSERVERS = 2122776651,

            [Description("msRTCSIP-PoolData")]
            ATT_MS_RTC_SIP_POOLDATA = 2122776652,

            [Description("msRTCSIP-EdgeProxyFQDN")]
            ATT_MS_RTC_SIP_EDGEPROXYFQDN = 2122776653,

            [Description("msRTCSIP-EdgeProxyData")]
            ATT_MS_RTC_SIP_EDGEPROXYDATA = 2122776654,

            [Description("msRTCSIP-ArchivingServerData")]
            ATT_MS_RTC_SIP_ARCHIVINGSERVERDATA = 2122776659,

            [Description("msRTCSIP-ArchivingServerVersion")]
            ATT_MS_RTC_SIP_ARCHIVINGSERVERVERSION = 2122776684,

            [Description("msRTCSIP-TrustedServerVersion")]
            ATT_MS_RTC_SIP_TRUSTEDSERVERVERSION = 2122776660,

            [Description("msRTCSIP-ArchiveDefaultFlags")]
            ATT_MS_RTC_SIP_ARCHIVEDEFAULTFLAGS = 2122776661,

            [Description("msRTCSIP-UserExtension")]
            ATT_MS_RTC_SIP_USEREXTENSION = 2122776639,

            [Description("msRTCSIP-Line")]
            ATT_MS_RTC_SIP_LINE = 2122776664,

            [Description("msRTCSIP-PoolVersion")]
            ATT_MS_RTC_SIP_POOLVERSION = 2122776667,

            [Description("msRTCSIP-OptionFlags")]
            ATT_MS_RTC_SIP_OPTIONFLAGS = 2122776663,

            [Description("msRTCSIP-LineServer")]
            ATT_MS_RTC_SIP_LINESERVER = 2122776665,

            [Description("msRTCSIP-PoolFunctionality")]
            ATT_MS_RTC_SIP_POOLFUNCTIONALITY = 2122776666,

            [Description("msRTCSIP-MeetingFlags")]
            ATT_MS_RTC_SIP_MEETINGFLAGS = 2122776668,

            [Description("msRTCSIP-PolicyData")]
            ATT_MS_RTC_SIP_POLICYDATA = 2122776673,

            [Description("msRTCSIP-MCUFactoryAddress")]
            ATT_MS_RTC_SIP_MCUFACTORYADDRESS = 2122776680,

            [Description("msRTCSIP-MCUData")]
            ATT_MS_RTC_SIP_MCUDATA = 2122776681,

            [Description("msRTCSIP-MCUFactoryPath")]
            ATT_MS_RTC_SIP_MCUFACTORYPATH = 2122776683,

            [Description("msRTCSIP-PoolAddresses")]
            ATT_MS_RTC_SIP_POOLADDRESSES = 2122776674,

            [Description("msRTCSIP-MCUType")]
            ATT_MS_RTC_SIP_MCUTYPE = 2122776676,

            [Description("msRTCSIP-MCUServers")]
            ATT_MS_RTC_SIP_MCUSERVERS = 2122776677,

            [Description("msRTCSIP-MCUVendor")]
            ATT_MS_RTC_SIP_MCUVENDOR = 2122776678,

            [Description("msRTCSIP-MCUFactoryData")]
            ATT_MS_RTC_SIP_MCUFACTORYDATA = 2122776679,

            [Description("msRTCSIP-ArchivingEnabled")]
            ATT_MS_RTC_SIP_ARCHIVINGENABLED = 2122776656,

            [Description("msRTCSIP-WebComponentsPoolAddress")]
            ATT_MS_RTC_SIP_WEBCOMPONENTSPOOLADDRESS = 2122776686,

            [Description("msRTCSIP-WebComponentsData")]
            ATT_MS_RTC_SIP_WEBCOMPONENTSDATA = 2122776687,

            [Description("msRTCSIP-WebComponentsServers")]
            ATT_MS_RTC_SIP_WEBCOMPONENTSSERVERS = 2122776688,

            [Description("msRTCSIP-TrustedMCUFQDN")]
            ATT_MS_RTC_SIP_TRUSTEDMCUFQDN = 2122776689,

            [Description("msRTCSIP-TrustedMCUData")]
            ATT_MS_RTC_SIP_TRUSTEDMCUDATA = 2122776690,

            [Description("msRTCSIP-TrustedWebComponentsServerFQDN")]
            ATT_MS_RTC_SIP_TRUSTEDWEBCOMPONENTSSERVERFQDN = 2122776691,

            [Description("msRTCSIP-TrustedWebComponentsServerData")]
            ATT_MS_RTC_SIP_TRUSTEDWEBCOMPONENTSSERVERDATA = 2122776692,

            [Description("msRTCSIP-MCUFactoryProviderID")]
            ATT_MS_RTC_SIP_MCUFACTORYPROVIDERID = 2122776694,

            [Description("msRTCSIP-PoolDomainFQDN")]
            ATT_MS_RTC_SIP_POOLDOMAINFQDN = 2122776695,

            [Description("msRTCSIP-OriginatorSid")]
            ATT_MS_RTC_SIP_ORIGINATORSID = 2122776626,

            [Description("msRTCSIP-SourceObjectType")]
            ATT_MS_RTC_SIP_SOURCEOBJECTTYPE = 2122776698,

            [Description("msDS-SourceObjectDN")]
            ATT_MS_DS_SOURCE_OBJECT_DN = 591703,

            [Description("msRTCSIP-PolicyType")]
            ATT_MS_RTC_SIP_POLICYTYPE = 2122776699,

            [Description("msRTCSIP-PolicyContent")]
            ATT_MS_RTC_SIP_POLICYCONTENT = 2122776700,

            [Description("msRTCSIP-TrustedProxyFQDN")]
            ATT_MS_RTC_SIP_TRUSTEDPROXYFQDN = 2122776706,

            [Description("msRTCSIP-TrustedProxyData")]
            ATT_MS_RTC_SIP_TRUSTEDPROXYDATA = 2122776707,

            [Description("msRTCSIP-DefaultPolicy")]
            ATT_MS_RTC_SIP_DEFAULTPOLICY = 2122776705,

            [Description("msRTCSIP-UserPolicy")]
            ATT_MS_RTC_SIP_USERPOLICY = 2122776708,

            [Description("msRTCSIP-ExtensionData")]
            ATT_MS_RTC_SIP_EXTENSIONDATA = 2122776713,

            [Description("msRTCSIP-UCFlags")]
            ATT_MS_RTC_SIP_UCFLAGS = 2122776709,

            [Description("msRTCSIP-UCPolicy")]
            ATT_MS_RTC_SIP_UCPOLICY = 2122776710,

            [Description("msRTCSIP-LocationName")]
            ATT_MS_RTC_SIP_LOCATIONNAME = 2122776715,

            [Description("msRTCSIP-Description")]
            ATT_MS_RTC_SIP_DESCRIPTION = 2122776719,

            [Description("msRTCSIP-RuleName")]
            ATT_MS_RTC_SIP_RULENAME = 2122776722,

            [Description("msRTCSIP-Pattern")]
            ATT_MS_RTC_SIP_PATTERN = 2122776723,

            [Description("msRTCSIP-Translation")]
            ATT_MS_RTC_SIP_TRANSLATION = 2122776724,

            [Description("msRTCSIP-RouteUsageAttribute")]
            ATT_MS_RTC_SIP_ROUTEUSAGEATTRIBUTE = 2122776727,

            [Description("msRTCSIP-PhoneRouteName")]
            ATT_MS_RTC_SIP_PHONEROUTENAME = 2122776729,

            [Description("msRTCSIP-Gateways")]
            ATT_MS_RTC_SIP_GATEWAYS = 2122776731,

            [Description("msRTCSIP-TargetPhoneNumber")]
            ATT_MS_RTC_SIP_TARGETPHONENUMBER = 2122776740,

            [Description("msRTCSIP-RouteUsageLinks")]
            ATT_MS_RTC_SIP_ROUTEUSAGELINKS = 2122776741,

            [Description("msRTCSIP-PhoneRouteBL")]
            ATT_MS_RTC_SIP_PHONEROUTEBL = 2122776742,

            [Description("msRTCSIP-LocalNormalizationLinks")]
            ATT_MS_RTC_SIP_LOCALNORMALIZATIONLINKS = 2122776743,

            [Description("msRTCSIP-LocationProfileBL")]
            ATT_MS_RTC_SIP_LOCATIONPROFILEBL = 2122776744,

            [Description("msRTCSIP-MeetingPolicy")]
            ATT_MS_RTC_SIP_MEETINGPOLICY = 2122776669,

            [Description("msRTCSIP-Default")]
            ATT_MS_RTC_SIP_DEFAULT = 2122776745,

            [Description("msRTCSIP-TrustedServicePort")]
            ATT_MS_RTC_SIP_TRUSTEDSERVICEPORT = 2122776746,

            [Description("msRTCSIP-Routable")]
            ATT_MS_RTC_SIP_ROUTABLE = 2122776748,

            [Description("msRTCSIP-TrustedServiceLinks")]
            ATT_MS_RTC_SIP_TRUSTEDSERVICELINKS = 2122776749,

            [Description("msRTCSIP-ServerBL")]
            ATT_MS_RTC_SIP_SERVERBL = 2122776750,

            [Description("msRTCSIP-DefaultLocationProfileLink")]
            ATT_MS_RTC_SIP_DEFAULTLOCATIONPROFILELINK = 2122776751,

            [Description("msRTCSIP-ServerReferenceBL")]
            ATT_MS_RTC_SIP_SERVERREFERENCEBL = 2122776752,

            [Description("msRTCSIP-TrustedServiceType")]
            ATT_MS_RTC_SIP_TRUSTEDSERVICETYPE = 2122776747,

            [Description("msRTCSIP-ApplicationDestination")]
            ATT_MS_RTC_SIP_APPLICATIONDESTINATION = 2122776753,

            [Description("msRTCSIP-ApplicationOptions")]
            ATT_MS_RTC_SIP_APPLICATIONOPTIONS = 2122776754,

            [Description("msRTCSIP-ApplicationList")]
            ATT_MS_RTC_SIP_APPLICATIONLIST = 2122776755,

            [Description("msRTCSIP-ApplicationServerPoolLink")]
            ATT_MS_RTC_SIP_APPLICATIONSERVERPOOLLINK = 2122776756,

            [Description("msRTCSIP-ApplicationServerBL")]
            ATT_MS_RTC_SIP_APPLICATIONSERVERBL = 2122776757,

            [Description("msRTCSIP-UserLocationProfile")]
            ATT_MS_RTC_SIP_USERLOCATIONPROFILE = 2122776758,

            [Description("msRTCSIP-MappingContact")]
            ATT_MS_RTC_SIP_MAPPINGCONTACT = 2122776760,

            [Description("msRTCSIP-MappingLocation")]
            ATT_MS_RTC_SIP_MAPPINGLOCATION = 2122776761,

            [Description("msRTCSIP-LocationProfileOptions")]
            ATT_MS_RTC_SIP_LOCATIONPROFILEOPTIONS = 2122776762,

            [Description("msRTCSIP-ExternalAccessCode")]
            ATT_MS_RTC_SIP_EXTERNALACCESSCODE = 2122776763,

            [Description("msRTCSIP-LocalNormalizationOptions")]
            ATT_MS_RTC_SIP_LOCALNORMALIZATIONOPTIONS = 2122776764,

            [Description("msRTCSIP-ConferenceDirectoryId")]
            ATT_MS_RTC_SIP_CONFERENCEDIRECTORYID = 2122776767,

            [Description("msRTCSIP-ConferenceDirectoryHomePool")]
            ATT_MS_RTC_SIP_CONFERENCEDIRECTORYHOMEPOOL = 2122776768,

            [Description("msRTCSIP-ConferenceDirectoryTargetPool")]
            ATT_MS_RTC_SIP_CONFERENCEDIRECTORYTARGETPOOL = 2122776769,

            [Description("msRTCSIP-MobilityFlags")]
            ATT_MS_RTC_SIP_MOBILITYFLAGS = 2122776770,

            [Description("msRTCSIP-MobilityPolicy")]
            ATT_MS_RTC_SIP_MOBILITYPOLICY = 2122776771,

            [Description("msRTCSIP-PresenceFlags")]
            ATT_MS_RTC_SIP_PRESENCEFLAGS = 2122776772,

            [Description("msRTCSIP-PresencePolicy")]
            ATT_MS_RTC_SIP_PRESENCEPOLICY = 2122776773,

            [Description("msRTCSIP-DefaultCWAInternalURL")]
            ATT_MS_RTC_SIP_DEFAULTCWAINTERNALURL = 2122776774,

            [Description("msRTCSIP-DefaultCWAExternalURL")]
            ATT_MS_RTC_SIP_DEFAULTCWAEXTERNALURL = 2122776775,

            [Description("msRTCSIP-TrustedServiceFlags")]
            ATT_MS_RTC_SIP_TRUSTEDSERVICEFLAGS = 2122776776,

            [Description("msRTCSIP-RoutingPoolDN")]
            ATT_MS_RTC_SIP_ROUTINGPOOLDN = 2122776777,

            [Description("msRTCSIP-TrustedServerFQDN")]
            ATT_MS_RTC_SIP_TRUSTEDSERVERFQDN = 2122776632,

            [Description("msRTCSIP-ApplicationPrimaryLanguage")]
            ATT_MS_RTC_SIP_APPLICATIONPRIMARYLANGUAGE = 2122776765,

            [Description("msRTCSIP-ApplicationSecondaryLanguages")]
            ATT_MS_RTC_SIP_APPLICATIONSECONDARYLANGUAGES = 2122776766,

            [Description("msRTCSIP-SchemaVersion")]
            ATT_MS_RTC_SIP_SCHEMAVERSION = 2122776622,

            [Description("gecos")]
            ATT_GECOS = 2424834,

            [Description("bootFile")]
            ATT_BOOTFILE = 2424856,

            [Description("memberUid")]
            ATT_MEMBERUID = 2424844,

            [Description("gidNumber")]
            ATT_GIDNUMBER = 2424833,

            [Description("shadowMin")]
            ATT_SHADOWMIN = 2424838,

            [Description("uidNumber")]
            ATT_UIDNUMBER = 2424832,

            [Description("shadowMax")]
            ATT_SHADOWMAX = 2424839,

            [Description("macAddress")]
            ATT_MACADDRESS = 2424854,

            [Description("shadowFlag")]
            ATT_SHADOWFLAG = 2424843,

            [Description("nisMapName")]
            ATT_NISMAPNAME = 2424858,

            [Description("loginShell")]
            ATT_LOGINSHELL = 2424836,

            [Description("msSFU30Name")]
            ATT_MSSFU_30_NAME = 2162997,

            [Description("msDFSR-Flags")]
            ATT_MS_DFSR_FLAGS = 2293776,

            [Description("nisMapEntry")]
            ATT_NISMAPENTRY = 2424859,

            [Description("oncRpcNumber")]
            ATT_ONCRPCNUMBER = 2424850,

            [Description("ipHostNumber")]
            ATT_IPHOSTNUMBER = 2424851,

            [Description("shadowExpire")]
            ATT_SHADOWEXPIRE = 2424842,

            [Description("msDFSR-Enabled")]
            ATT_MS_DFSR_ENABLED = 2293769,

            [Description("msDFSR-DfsPath")]
            ATT_MS_DFSR_DFSPATH = 2293781,

            [Description("bootParameter")]
            ATT_BOOTPARAMETER = 2424855,

            [Description("msSFU30Aliases")]
            ATT_MSSFU_30_ALIASES = 2163011,

            [Description("msSFU30Domains")]
            ATT_MSSFU_30_DOMAINS = 2163028,

            [Description("ipServicePort")]
            ATT_IPSERVICEPORT = 2424847,

            [Description("msDFSR-Version")]
            ATT_MS_DFSR_VERSION = 2293761,

            [Description("msDFSR-Options")]
            ATT_MS_DFSR_OPTIONS = 2293777,

            [Description("shadowWarning")]
            ATT_SHADOWWARNING = 2424840,

            [Description("msDFSR-Schedule")]
            ATT_MS_DFSR_SCHEDULE = 2293774,

            [Description("shadowInactive")]
            ATT_SHADOWINACTIVE = 2424841,

            [Description("msDFSR-RootPath")]
            ATT_MS_DFSR_ROOTPATH = 2293763,

            [Description("msDFSR-Keywords")]
            ATT_MS_DFSR_KEYWORDS = 2293775,

            [Description("msDFSR-RootFence")]
            ATT_MS_DFSR_ROOTFENCE = 2293782,

            [Description("msSFU30NisDomain")]
            ATT_MSSFU_30_NIS_DOMAIN = 2163027,

            [Description("ipNetmaskNumber")]
            ATT_IPNETMASKNUMBER = 2424853,

            [Description("msSFU30MapFilter")]
            ATT_MSSFU_30_MAP_FILTER = 2162994,

            [Description("msDFSR-Extension")]
            ATT_MS_DFSR_EXTENSION = 2293762,

            [Description("ipNetworkNumber")]
            ATT_IPNETWORKNUMBER = 2424852,

            [Description("msSFU30KeyValues")]
            ATT_MSSFU_30_KEY_VALUES = 2163012,

            [Description("msSFU30YpServers")]
            ATT_MSSFU_30_YP_SERVERS = 2163029,

            [Description("msDFSR-RdcEnabled")]
            ATT_MS_DFSR_RDCENABLED = 2293779,

            [Description("shadowLastChange")]
            ATT_SHADOWLASTCHANGE = 2424837,

            [Description("msDFSR-FileFilter")]
            ATT_MS_DFSR_FILEFILTER = 2293772,

            [Description("ipProtocolNumber")]
            ATT_IPPROTOCOLNUMBER = 2424849,

            [Description("unixUserPassword")]
            ATT_UNIXUSERPASSWORD = 591734,

            [Description("msDFSR-StagingPath")]
            ATT_MS_DFSR_STAGINGPATH = 2293765,

            [Description("memberNisNetgroup")]
            ATT_MEMBERNISNETGROUP = 2424845,

            [Description("msSFU30OrderNumber")]
            ATT_MSSFU_30_ORDER_NUMBER = 2162996,

            [Description("ipServiceProtocol")]
            ATT_IPSERVICEPROTOCOL = 2424848,

            [Description("unixHomeDirectory")]
            ATT_UNIXHOMEDIRECTORY = 2424835,

            [Description("msSFU30CryptMethod")]
            ATT_MSSFU_30_CRYPT_METHOD = 2163040,

            [Description("nisNetgroupTriple")]
            ATT_NISNETGROUPTRIPLE = 2424846,

            [Description("msDFSR-ConflictPath")]
            ATT_MS_DFSR_CONFLICTPATH = 2293767,

            [Description("msSFU30MaxGidNumber")]
            ATT_MSSFU_30_MAX_GID_NUMBER = 2163030,

            [Description("msSFU30MaxUidNumber")]
            ATT_MSSFU_30_MAX_UID_NUMBER = 2163031,

            [Description("msDFSR-DfsLinkTarget")]
            ATT_MS_DFSR_DFSLINKTARGET = 2293784,

            [Description("msSFU30PosixMemberOf")]
            ATT_MSSFU_30_POSIX_MEMBER_OF = 2163035,

            [Description("msSFU30KeyAttributes")]
            ATT_MSSFU_30_KEY_ATTRIBUTES = 2162989,

            [Description("msSFU30FieldSeparator")]
            ATT_MSSFU_30_FIELD_SEPARATOR = 2162990,

            [Description("msDFSR-ContentSetGuid")]
            ATT_MS_DFSR_CONTENTSETGUID = 2293778,

            [Description("msDFSR-MemberReference")]
            ATT_MS_DFSR_MEMBERREFERENCE = 2293860,

            [Description("msSFU30SearchContainer")]
            ATT_MSSFU_30_SEARCH_CONTAINER = 2162988,

            [Description("msDFSR-StagingSizeInMb")]
            ATT_MS_DFSR_STAGINGSIZEINMB = 2293766,

            [Description("msDFSR-DirectoryFilter")]
            ATT_MS_DFSR_DIRECTORYFILTER = 2293773,

            [Description("msDFSR-ConflictSizeInMb")]
            ATT_MS_DFSR_CONFLICTSIZEINMB = 2293768,

            [Description("msSFU30IsValidContainer")]
            ATT_MSSFU_30_IS_VALID_CONTAINER = 2163038,

            [Description("msSFU30SearchAttributes")]
            ATT_MSSFU_30_SEARCH_ATTRIBUTES = 2162992,

            [Description("msSFU30MasterServerName")]
            ATT_MSSFU_30_MASTER_SERVER_NAME = 2162995,

            [Description("msSFU30ResultAttributes")]
            ATT_MSSFU_30_RESULT_ATTRIBUTES = 2162993,

            [Description("msDFSR-MemberReferenceBL")]
            ATT_MS_DFSR_MEMBERREFERENCEBL = 2293862,

            [Description("msDFSR-ComputerReference")]
            ATT_MS_DFSR_COMPUTERREFERENCE = 2293861,

            [Description("msDFSR-RdcMinFileSizeInKb")]
            ATT_MS_DFSR_RDCMINFILESIZEINKB = 2293780,

            [Description("msSFU30NSMAPFieldPosition")]
            ATT_MSSFU_30_NSMAP_FIELD_POSITION = 2163033,

            [Description("msDFSR-ComputerReferenceBL")]
            ATT_MS_DFSR_COMPUTERREFERENCEBL = 2293863,

            [Description("msSFU30IntraFieldSeparator")]
            ATT_MSSFU_30_INTRA_FIELD_SEPARATOR = 2162991,

            [Description("msDFSR-ReplicationGroupGuid")]
            ATT_MS_DFSR_REPLICATIONGROUPGUID = 2293783,

            [Description("msSFU30NetgroupHostAtDomain")]
            ATT_MSSFU_30_NETGROUP_HOST_AT_DOMAIN = 2163036,

            [Description("msSFU30NetgroupUserAtDomain")]
            ATT_MSSFU_30_NETGROUP_USER_AT_DOMAIN = 2163037,

            [Description("msDFSR-ReplicationGroupType")]
            ATT_MS_DFSR_REPLICATIONGROUPTYPE = 2293770,

            [Description("msDFSR-TombstoneExpiryInMin")]
            ATT_MS_DFSR_TOMBSTONEEXPIRYINMIN = 2293771,

            [Description("msDS-IsDomainFor")]
            ATT_MS_DS_IS_DOMAIN_FOR = 591757,

            [Description("msDS-IsFullReplicaFor")]
            ATT_MS_DS_IS_FULL_REPLICA_FOR = 591756,

            [Description("msDS-IsPartialReplicaFor")]
            ATT_MS_DS_IS_PARTIAL_REPLICA_FOR = 591758,

            [Description("msDS-PromotionSettings")]
            ATT_MS_DS_PROMOTION_SETTINGS = 591786,

            [Description("msDFSR-ReadOnly")]
            ATT_MS_DFSR_READONLY = 2293788,

            [Description("msDFSR-Priority")]
            ATT_MS_DFSR_PRIORITY = 2293785,

            [Description("msDS-AzObjectGuid")]
            ATT_MS_DS_AZ_OBJECT_GUID = 591773,

            [Description("msDS-AzGenericData")]
            ATT_MS_DS_AZ_GENERIC_DATA = 591774,

            [Description("msDFSR-CachePolicy")]
            ATT_MS_DFSR_CACHEPOLICY = 2293789,

            [Description("msDFSR-DeletedPath")]
            ATT_MS_DFSR_DELETEDPATH = 2293786,

            [Description("msDFSR-DeletedSizeInMb")]
            ATT_MS_DFSR_DELETEDSIZEINMB = 2293787,

            [Description("ms-net-ieee-8023-GP-PolicyData")]
            ATT_MS_NET_IEEE_8023_GP_POLICYDATA = 591779,

            [Description("ms-net-ieee-8023-GP-PolicyGUID")]
            ATT_MS_NET_IEEE_8023_GP_POLICYGUID = 591778,

            [Description("msDFSR-MaxAgeInCacheInMin")]
            ATT_MS_DFSR_MAXAGEINCACHEINMIN = 2293791,

            [Description("ms-net-ieee-80211-GP-PolicyData")]
            ATT_MS_NET_IEEE_80211_GP_POLICYDATA = 591776,

            [Description("ms-net-ieee-80211-GP-PolicyGUID")]
            ATT_MS_NET_IEEE_80211_GP_POLICYGUID = 591775,

            [Description("msDS-NC-RO-Replica-Locations-BL")]
            ATT_MS_DS_NC_RO_REPLICA_LOCATIONS_BL = 591792,

            [Description("msDFSR-MinDurationCacheInMin")]
            ATT_MS_DFSR_MINDURATIONCACHEINMIN = 2293790,

            [Description("ms-net-ieee-8023-GP-PolicyReserved")]
            ATT_MS_NET_IEEE_8023_GP_POLICYRESERVED = 591780,

            [Description("ms-net-ieee-80211-GP-PolicyReserved")]
            ATT_MS_NET_IEEE_80211_GP_POLICYRESERVED = 591777,

            [Description("msDFSR-RootSizeInMb")]
            ATT_MS_DFSR_ROOTSIZEINMB = 2293764,

            [Description("msNPAllowDialin")]
            ATT_MSNPALLOWDIALIN = 590943,

            [Description("msNPCallingStationID")]
            ATT_MSNPCALLINGSTATIONID = 590948,

            [Description("msNPSavedCallingStationID")]
            ATT_MSNPSAVEDCALLINGSTATIONID = 590954,

            [Description("msRADIUSCallbackNumber")]
            ATT_MSRADIUSCALLBACKNUMBER = 590969,

            [Description("msRADIUSFramedIPAddress")]
            ATT_MSRADIUSFRAMEDIPADDRESS = 590977,

            [Description("msRADIUSFramedRoute")]
            ATT_MSRADIUSFRAMEDROUTE = 590982,

            [Description("msRADIUSServiceType")]
            ATT_MSRADIUSSERVICETYPE = 590995,

            [Description("msRASSavedCallbackNumber")]
            ATT_MSRASSAVEDCALLBACKNUMBER = 591013,

            [Description("msRASSavedFramedIPAddress")]
            ATT_MSRASSAVEDFRAMEDIPADDRESS = 591014,

            [Description("msRASSavedFramedRoute")]
            ATT_MSRASSAVEDFRAMEDROUTE = 591015,

            [Description("msRADIUS-FramedInterfaceId")]
            ATT_MS_RADIUS_FRAMEDINTERFACEID = 591737,

            [Description("msRADIUS-SavedFramedInterfaceId")]
            ATT_MS_RADIUS_SAVEDFRAMEDINTERFACEID = 591738,

            [Description("msRADIUS-FramedIpv6Prefix")]
            ATT_MS_RADIUS_FRAMEDIPV6PREFIX = 591739,

            [Description("msRADIUS-SavedFramedIpv6Prefix")]
            ATT_MS_RADIUS_SAVEDFRAMEDIPV6PREFIX = 591740,

            [Description("msRADIUS-FramedIpv6Route")]
            ATT_MS_RADIUS_FRAMEDIPV6ROUTE = 591741,

            [Description("msRADIUS-SavedFramedIpv6Route")]
            ATT_MS_RADIUS_SAVEDFRAMEDIPV6ROUTE = 591742,

            [Description("msDFSR-OnDemandExclusionDirectoryFilter")]
            ATT_MS_DFSR_ONDEMANDEXCLUSIONDIRECTORYFILTER = 2293796,

            [Description("msDFSR-DefaultCompressionExclusionFilter")]
            ATT_MS_DFSR_DEFAULTCOMPRESSIONEXCLUSIONFILTER = 2293794,

            [Description("msTSHomeDrive")]
            ATT_MS_TS_HOME_DRIVE = 591802,

            [Description("msTSProperty01")]
            ATT_MS_TS_PROPERTY01 = 591815,

            [Description("msTSProperty02")]
            ATT_MS_TS_PROPERTY02 = 591816,

            [Description("msTSAllowLogon")]
            ATT_MS_TS_ALLOW_LOGON = 591803,

            [Description("msDFSR-Options2")]
            ATT_MS_DFSR_OPTIONS2 = 2293797,

            [Description("msTSProfilePath")]
            ATT_MS_TS_PROFILE_PATH = 591800,

            [Description("msTSMaxIdleTime")]
            ATT_MS_TS_MAX_IDLE_TIME = 591807,

            [Description("msTSHomeDirectory")]
            ATT_MS_TS_HOME_DIRECTORY = 591801,

            [Description("msTSRemoteControl")]
            ATT_MS_TS_REMOTE_CONTROL = 591804,

            [Description("msTSWorkDirectory")]
            ATT_MS_TS_WORK_DIRECTORY = 591813,

            [Description("msTSInitialProgram")]
            ATT_MS_TS_INITIAL_PROGRAM = 591814,

            [Description("msTSMaxConnectionTime")]
            ATT_MS_TS_MAX_CONNECTION_TIME = 591806,

            [Description("msTSReconnectionAction")]
            ATT_MS_TS_RECONNECTION_ACTION = 591808,

            [Description("msTSConnectClientDrives")]
            ATT_MS_TS_CONNECT_CLIENT_DRIVES = 591810,

            [Description("msDFSR-CommonStagingPath")]
            ATT_MS_DFSR_COMMONSTAGINGPATH = 2293798,

            [Description("msTSMaxDisconnectionTime")]
            ATT_MS_TS_MAX_DISCONNECTION_TIME = 591805,

            [Description("msTSDefaultToMainPrinter")]
            ATT_MS_TS_DEFAULT_TO_MAIN_PRINTER = 591812,

            [Description("msTSConnectPrinterDrives")]
            ATT_MS_TS_CONNECT_PRINTER_DRIVES = 591811,

            [Description("msTSBrokenConnectionAction")]
            ATT_MS_TS_BROKEN_CONNECTION_ACTION = 591809,

            [Description("msDFSR-DisablePacketPrivacy")]
            ATT_MS_DFSR_DISABLEPACKETPRIVACY = 2293792,

            [Description("msDFSR-CommonStagingSizeInMb")]
            ATT_MS_DFSR_COMMONSTAGINGSIZEINMB = 2293799,

            [Description("msDFSR-OnDemandExclusionFileFilter")]
            ATT_MS_DFSR_ONDEMANDEXCLUSIONFILEFILTER = 2293795,

            [Description("msDFSR-StagingCleanupTriggerInPercent")]
            ATT_MS_DFSR_STAGINGCLEANUPTRIGGERINPERCENT = 2293800,

            [Description("msTSLicenseVersion")]
            ATT_MS_TS_LICENSEVERSION = 591818,

            [Description("msTSManagingLS")]
            ATT_MS_TS_MANAGINGLS = 591819,

            [Description("terminalServer")]
            ATT_TERMINAL_SERVER = 590709,

            [Description("msSFU30PosixMember")]
            ATT_MSSFU_30_POSIX_MEMBER = 2163034,

            [Description("msDS-PSOAppliesTo")]
            ATT_MS_DS_PSO_APPLIES_TO = 591844,

            [Description("msTSManagingLS2")]
            ATT_MS_TS_MANAGINGLS2 = 591826,

            [Description("msTSManagingLS3")]
            ATT_MS_TS_MANAGINGLS3 = 591829,

            [Description("msTSManagingLS4")]
            ATT_MS_TS_MANAGINGLS4 = 591832,

            [Description("msTSExpireDate2")]
            ATT_MS_TS_EXPIREDATE2 = 591824,

            [Description("msTSExpireDate3")]
            ATT_MS_TS_EXPIREDATE3 = 591827,

            [Description("msTSExpireDate4")]
            ATT_MS_TS_EXPIREDATE4 = 591830,

            [Description("msTSLSProperty01")]
            ATT_MS_TSLS_PROPERTY01 = 591833,

            [Description("msTSLSProperty02")]
            ATT_MS_TSLS_PROPERTY02 = 591834,

            [Description("msTSLicenseVersion2")]
            ATT_MS_TS_LICENSEVERSION2 = 591825,

            [Description("msTSLicenseVersion3")]
            ATT_MS_TS_LICENSEVERSION3 = 591828,

            [Description("msTSLicenseVersion4")]
            ATT_MS_TS_LICENSEVERSION4 = 591831,

            [Description("title")]
            ATT_TITLE = 12,

            [Description("msFVE-RecoveryPassword")]
            ATT_MS_FVE_RECOVERYPASSWORD = 591788,

            [Description("msTPM-OwnerInformation")]
            ATT_MS_TPM_OWNERINFORMATION = 591790,

            [Description("msFVE-KeyPackage")]
            ATT_MS_FVE_KEYPACKAGE = 591823,

            [Description("thumbnailPhoto")]
            ATT_PICTURE = 1441827,

            [Description("accountExpires")]
            ATT_ACCOUNT_EXPIRES = 589983,

            [Description("streetAddress")]
            ATT_ADDRESS = 131328,

            [Description("addressBookRoots")]
            ATT_ADDRESS_BOOK_ROOTS = 591068,

            [Description("addressEntryDisplayTable")]
            ATT_ADDRESS_ENTRY_DISPLAY_TABLE = 131396,

            [Description("addressEntryDisplayTableMSDOS")]
            ATT_ADDRESS_ENTRY_DISPLAY_TABLE_MSDOS = 131472,

            [Description("addressSyntax")]
            ATT_ADDRESS_SYNTAX = 131327,

            [Description("addressType")]
            ATT_ADDRESS_TYPE = 131422,

            [Description("adminCount")]
            ATT_ADMIN_COUNT = 589974,

            [Description("adminDisplayName")]
            ATT_ADMIN_DISPLAY_NAME = 131266,

            [Description("allowedAttributes")]
            ATT_ALLOWED_ATTRIBUTES = 590737,

            [Description("allowedAttributesEffective")]
            ATT_ALLOWED_ATTRIBUTES_EFFECTIVE = 590738,

            [Description("allowedChildClasses")]
            ATT_ALLOWED_CHILD_CLASSES = 590735,

            [Description("allowedChildClassesEffective")]
            ATT_ALLOWED_CHILD_CLASSES_EFFECTIVE = 590736,

            [Description("altSecurityIdentities")]
            ATT_ALT_SECURITY_IDENTITIES = 590691,

            [Description("aNR")]
            ATT_ANR = 591032,

            [Description("attributeID")]
            ATT_ATTRIBUTE_ID = 131102,

            [Description("attributeSecurityGUID")]
            ATT_ATTRIBUTE_SECURITY_GUID = 589973,

            [Description("attributeSyntax")]
            ATT_ATTRIBUTE_SYNTAX = 131104,

            [Description("attributeTypes")]
            ATT_ATTRIBUTE_TYPES = 1572869,

            [Description("auditingPolicy")]
            ATT_AUDITING_POLICY = 590026,

            [Description("authenticationOptions")]
            ATT_AUTHENTICATION_OPTIONS = 589835,

            [Description("auxiliaryClass")]
            ATT_AUXILIARY_CLASS = 131423,

            [Description("badPasswordTime")]
            ATT_BAD_PASSWORD_TIME = 589873,

            [Description("badPwdCount")]
            ATT_BAD_PWD_COUNT = 589836,

            [Description("bridgeheadServerListBL")]
            ATT_BRIDGEHEAD_SERVER_LIST_BL = 590644,

            [Description("canonicalName")]
            ATT_CANONICAL_NAME = 590740,

            [Description("codePage")]
            ATT_CODE_PAGE = 589840,

            [Description("cn")]
            ATT_COMMON_NAME = 3,

            [Description("cost")]
            ATT_COST = 131207,

            [Description("countryCode")]
            ATT_COUNTRY_CODE = 589849,

            [Description("c")]
            ATT_COUNTRY_NAME = 6,

            [Description("createTimeStamp")]
            ATT_CREATE_TIME_STAMP = 1638401,

            [Description("creationTime")]
            ATT_CREATION_TIME = 589850,

            [Description("currentValue")]
            ATT_CURRENT_VALUE = 589851,

            [Description("dBCSPwd")]
            ATT_DBCS_PWD = 589879,

            [Description("defaultHidingValue")]
            ATT_DEFAULT_HIDING_VALUE = 590342,

            [Description("defaultObjectCategory")]
            ATT_DEFAULT_OBJECT_CATEGORY = 590607,

            [Description("defaultSecurityDescriptor")]
            ATT_DEFAULT_SECURITY_DESCRIPTOR = 590048,

            [Description("description")]
            ATT_DESCRIPTION = 13,

            [Description("displayName")]
            ATT_DISPLAY_NAME = 131085,

            [Description("displayNamePrintable")]
            ATT_DISPLAY_NAME_PRINTABLE = 131425,

            [Description("dITContentRules")]
            ATT_DIT_CONTENT_RULES = 1572866,

            [Description("dMDLocation")]
            ATT_DMD_LOCATION = 131108,

            [Description("dNReferenceUpdate")]
            ATT_DN_REFERENCE_UPDATE = 591066,

            [Description("dNSHostName")]
            ATT_DNS_HOST_NAME = 590443,

            [Description("dnsRoot")]
            ATT_DNS_ROOT = 589852,

            [Description("dc")]
            ATT_DOMAIN_COMPONENT = 1376281,

            [Description("domainCrossRef")]
            ATT_DOMAIN_CROSS_REF = 590296,

            [Description("domainReplica")]
            ATT_DOMAIN_REPLICA = 589982,

            [Description("dSCorePropagationData")]
            ATT_DS_CORE_PROPAGATION_DATA = 591181,

            [Description("dSHeuristics")]
            ATT_DS_HEURISTICS = 131284,

            [Description("dSASignature")]
            ATT_DSA_SIGNATURE = 131146,

            [Description("eFSPolicy")]
            ATT_EFSPOLICY = 590092,

            [Description("Enabled")]
            ATT_ENABLED = 131629,

            [Description("enabledConnection")]
            ATT_ENABLED_CONNECTION = 589860,

            [Description("extendedAttributeInfo")]
            ATT_EXTENDED_ATTRIBUTE_INFO = 590733,

            [Description("extendedCharsAllowed")]
            ATT_EXTENDED_CHARS_ALLOWED = 131452,

            [Description("extendedClassInfo")]
            ATT_EXTENDED_CLASS_INFO = 590732,

            [Description("flatName")]
            ATT_FLAT_NAME = 590335,

            [Description("forceLogoff")]
            ATT_FORCE_LOGOFF = 589863,

            [Description("fromEntry")]
            ATT_FROM_ENTRY = 590734,

            [Description("fromServer")]
            ATT_FROM_SERVER = 589864,

            [Description("fSMORoleOwner")]
            ATT_FSMO_ROLE_OWNER = 590193,

            [Description("garbageCollPeriod")]
            ATT_GARBAGE_COLL_PERIOD = 131373,

            [Description("givenName")]
            ATT_GIVEN_NAME = 42,

            [Description("globalAddressList")]
            ATT_GLOBAL_ADDRESS_LIST = 591069,

            [Description("governsID")]
            ATT_GOVERNS_ID = 131094,

            [Description("groupType")]
            ATT_GROUP_TYPE = 590574,

            [Description("hasMasterNCs")]
            ATT_HAS_MASTER_NCS = 131086,

            [Description("hasPartialReplicaNCs")]
            ATT_HAS_PARTIAL_REPLICA_NCS = 131087,

            [Description("helpData16")]
            ATT_HELP_DATA16 = 131474,

            [Description("helpData32")]
            ATT_HELP_DATA32 = 131081,

            [Description("helpFileName")]
            ATT_HELP_FILE_NAME = 131399,

            [Description("homeDirectory")]
            ATT_HOME_DIRECTORY = 589868,

            [Description("homeDrive")]
            ATT_HOME_DRIVE = 589869,

            [Description("initialAuthIncoming")]
            ATT_INITIAL_AUTH_INCOMING = 590363,

            [Description("initialAuthOutgoing")]
            ATT_INITIAL_AUTH_OUTGOING = 590364,

            [Description("instanceType")]
            ATT_INSTANCE_TYPE = 131073,

            [Description("interSiteTopologyFailover")]
            ATT_INTER_SITE_TOPOLOGY_FAILOVER = 591072,

            [Description("interSiteTopologyGenerator")]
            ATT_INTER_SITE_TOPOLOGY_GENERATOR = 591070,

            [Description("interSiteTopologyRenew")]
            ATT_INTER_SITE_TOPOLOGY_RENEW = 591071,

            [Description("invocationId")]
            ATT_INVOCATION_ID = 131187,

            [Description("isCriticalSystemObject")]
            ATT_IS_CRITICAL_SYSTEM_OBJECT = 590692,

            [Description("isDefunct")]
            ATT_IS_DEFUNCT = 590485,

            [Description("isDeleted")]
            ATT_IS_DELETED = 131120,

            [Description("memberOf")]
            ATT_IS_MEMBER_OF_DL = 131174,

            [Description("isMemberOfPartialAttributeSet")]
            ATT_IS_MEMBER_OF_PARTIAL_ATTRIBUTE_SET = 590463,

            [Description("isSingleValued")]
            ATT_IS_SINGLE_VALUED = 131105,

            [Description("keywords")]
            ATT_KEYWORDS = 589872,

            [Description("lastKnownParent")]
            ATT_LAST_KNOWN_PARENT = 590605,

            [Description("lastLogoff")]
            ATT_LAST_LOGOFF = 589875,

            [Description("lastLogon")]
            ATT_LAST_LOGON = 589876,

            [Description("lastSetTime")]
            ATT_LAST_SET_TIME = 589877,

            [Description("lDAPAdminLimits")]
            ATT_LDAP_ADMIN_LIMITS = 590667,

            [Description("lDAPDisplayName")]
            ATT_LDAP_DISPLAY_NAME = 131532,

            [Description("lDAPIPDenyList")]
            ATT_LDAP_IPDENY_LIST = 590668,

            [Description("legacyExchangeDN")]
            ATT_LEGACY_EXCHANGE_DN = 590479,

            [Description("linkID")]
            ATT_LINK_ID = 131122,

            [Description("lmPwdHistory")]
            ATT_LM_PWD_HISTORY = 589984,

            [Description("localPolicyFlags")]
            ATT_LOCAL_POLICY_FLAGS = 589880,

            [Description("l")]
            ATT_LOCALITY_NAME = 7,

            [Description("lockOutObservationWindow")]
            ATT_LOCK_OUT_OBSERVATION_WINDOW = 589885,

            [Description("lockoutDuration")]
            ATT_LOCKOUT_DURATION = 589884,

            [Description("lockoutThreshold")]
            ATT_LOCKOUT_THRESHOLD = 589897,

            [Description("lockoutTime")]
            ATT_LOCKOUT_TIME = 590486,

            [Description("thumbnailLogo")]
            ATT_LOGO = 1441828,

            [Description("logonCount")]
            ATT_LOGON_COUNT = 589993,

            [Description("logonHours")]
            ATT_LOGON_HOURS = 589888,

            [Description("machineRole")]
            ATT_MACHINE_ROLE = 589895,

            [Description("managedBy")]
            ATT_MANAGED_BY = 590477,

            [Description("mAPIID")]
            ATT_MAPI_ID = 131121,

            [Description("masteredBy")]
            ATT_MASTERED_BY = 591233,

            [Description("maxPwdAge")]
            ATT_MAX_PWD_AGE = 589898,

            [Description("maxRenewAge")]
            ATT_MAX_RENEW_AGE = 589899,

            [Description("maxTicketAge")]
            ATT_MAX_TICKET_AGE = 589901,

            [Description("mayContain")]
            ATT_MAY_CONTAIN = 131097,

            [Description("member")]
            ATT_MEMBER = 31,

            [Description("minPwdAge")]
            ATT_MIN_PWD_AGE = 589902,

            [Description("minPwdLength")]
            ATT_MIN_PWD_LENGTH = 589903,

            [Description("minTicketAge")]
            ATT_MIN_TICKET_AGE = 589904,

            [Description("modifiedCount")]
            ATT_MODIFIED_COUNT = 589992,

            [Description("modifiedCountAtLastProm")]
            ATT_MODIFIED_COUNT_AT_LAST_PROM = 589905,

            [Description("modifyTimeStamp")]
            ATT_MODIFY_TIME_STAMP = 1638402,

            [Description("msDS-AdditionalDnsHostName")]
            ATT_MS_DS_ADDITIONAL_DNS_HOST_NAME = 591541,

            [Description("msDS-AdditionalSamAccountName")]
            ATT_MS_DS_ADDITIONAL_SAM_ACCOUNT_NAME = 591542,

            [Description("msDS-AllUsersTrustQuota")]
            ATT_MS_DS_ALL_USERS_TRUST_QUOTA = 591613,

            [Description("msDS-AllowedDNSSuffixes")]
            ATT_MS_DS_ALLOWED_DNS_SUFFIXES = 591534,

            [Description("msDS-AllowedToDelegateTo")]
            ATT_MS_DS_ALLOWED_TO_DELEGATE_TO = 591611,

            [Description("msDS-Auxiliary-Classes")]
            ATT_MS_DS_AUXILIARY_CLASSES = 591282,

            [Description("msDS-Approx-Immed-Subordinates")]
            ATT_MS_DS_APPROX_IMMED_SUBORDINATES = 591493,

            [Description("msDS-AuthenticatedAtDC")]
            ATT_MS_DS_AUTHENTICATEDAT_DC = 591782,

            [Description("msDS-AuthenticatedToAccountlist")]
            ATT_MS_DS_AUTHENTICATEDTO_ACCOUNTLIST = 591781,

            [Description("msDS-AzLDAPQuery")]
            ATT_MS_DS_AZ_LDAP_QUERY = 591616,

            [Description("msDS-Behavior-Version")]
            ATT_MS_DS_BEHAVIOR_VERSION = 591283,

            [Description("msDS-Cached-Membership")]
            ATT_MS_DS_CACHED_MEMBERSHIP = 591265,

            [Description("msDS-Cached-Membership-Time-Stamp")]
            ATT_MS_DS_CACHED_MEMBERSHIP_TIME_STAMP = 591266,

            [Description("mS-DS-CreatorSID")]
            ATT_MS_DS_CREATOR_SID = 591234,

            [Description("msDS-DefaultQuota")]
            ATT_MS_DS_DEFAULT_QUOTA = 591670,

            [Description("msDS-DnsRootAlias")]
            ATT_MS_DS_DNSROOTALIAS = 591543,

            [Description("msDS-Entry-Time-To-Die")]
            ATT_MS_DS_ENTRY_TIME_TO_DIE = 591446,

            [Description("msDS-ExecuteScriptPassword")]
            ATT_MS_DS_EXECUTESCRIPTPASSWORD = 591607,

            [Description("msDS-HasInstantiatedNCs")]
            ATT_MS_DS_HAS_INSTANTIATED_NCS = 591533,

            [Description("msDS-HasDomainNCs")]
            ATT_MS_DS_HAS_DOMAIN_NCS = 591644,

            [Description("msDS-hasMasterNCs")]
            ATT_MS_DS_HAS_MASTER_NCS = 591660,

            [Description("msDS-IntId")]
            ATT_MS_DS_INTID = 591540,

            [Description("msDS-isGC")]
            ATT_MS_DS_ISGC = 591783,

            [Description("msDS-isRODC")]
            ATT_MS_DS_ISRODC = 591784,

            [Description("msDS-KeyVersionNumber")]
            ATT_MS_DS_KEYVERSIONNUMBER = 591606,

            [Description("msDS-LogonTimeSyncInterval")]
            ATT_MS_DS_LOGON_TIME_SYNC_INTERVAL = 591608,

            [Description("msDs-masteredBy")]
            ATT_MS_DS_MASTERED_BY = 591661,

            [Description("msDS-MaximumPasswordAge")]
            ATT_MS_DS_MAXIMUM_PASSWORD_AGE = 591835,

            [Description("msDS-MinimumPasswordAge")]
            ATT_MS_DS_MINIMUM_PASSWORD_AGE = 591836,

            [Description("msDS-MinimumPasswordLength")]
            ATT_MS_DS_MINIMUM_PASSWORD_LENGTH = 591837,

            [Description("msDS-PasswordHistoryLength")]
            ATT_MS_DS_PASSWORD_HISTORY_LENGTH = 591838,

            [Description("msDS-PasswordComplexityEnabled")]
            ATT_MS_DS_PASSWORD_COMPLEXITY_ENABLED = 591839,

            [Description("msDS-PasswordReversibleEncryptionEnabled")]
            ATT_MS_DS_PASSWORD_REVERSIBLE_ENCRYPTION_ENABLED = 591840,

            [Description("msDS-LockoutObservationWindow")]
            ATT_MS_DS_LOCKOUT_OBSERVATION_WINDOW = 591841,

            [Description("msDS-LockoutDuration")]
            ATT_MS_DS_LOCKOUT_DURATION = 591842,

            [Description("msDS-LockoutThreshold")]
            ATT_MS_DS_LOCKOUT_THRESHOLD = 591843,

            [Description("msDS-PSOApplied")]
            ATT_MS_DS_PSO_APPLIED = 591845,

            [Description("msDS-ResultantPSO")]
            ATT_MS_DS_RESULTANT_PSO = 591846,

            [Description("msDS-PasswordSettingsPrecedence")]
            ATT_MS_DS_PASSWORD_SETTINGS_PRECEDENCE = 591847,

            [Description("msDS-MembersForAzRole")]
            ATT_MS_DS_MEMBERS_FOR_AZ_ROLE = 591630,

            [Description("msDS-NcType")]
            ATT_MS_DS_NC_TYPE = 591848,

            [Description("msDS-NonMembers")]
            ATT_MS_DS_NON_MEMBERS = 591617,

            [Description("msDS-PhoneticDisplayName")]
            ATT_MS_DS_PHONETIC_DISPLAY_NAME = 591770,

            [Description("msDS-SiteName")]
            ATT_MS_DS_SITENAME = 591785,

            [Description("msDS-SupportedEncryptionTypes")]
            ATT_MS_DS_SUPPORTED_ENCRYPTION_TYPES = 591787,

            [Description("msDS-TrustForestTrustInfo")]
            ATT_MS_DS_TRUST_FOREST_TRUST_INFO = 591526,

            [Description("msDS-TombstoneQuotaFactor")]
            ATT_MS_DS_TOMBSTONE_QUOTA_FACTOR = 591671,

            [Description("msDS-TopQuotaUsage")]
            ATT_MS_DS_TOP_QUOTA_USAGE = 591674,

            [Description("ms-DS-MachineAccountQuota")]
            ATT_MS_DS_MACHINE_ACCOUNT_QUOTA = 591235,

            [Description("msDS-Other-Settings")]
            ATT_MS_DS_OTHER_SETTINGS = 591445,

            [Description("msDS-PrincipalName")]
            ATT_MS_DS_PRINCIPAL_NAME = 591689,

            [Description("msDS-QuotaAmount")]
            ATT_MS_DS_QUOTA_AMOUNT = 591669,

            [Description("msDS-QuotaEffective")]
            ATT_MS_DS_QUOTA_EFFECTIVE = 591672,

            [Description("msDS-QuotaTrustee")]
            ATT_MS_DS_QUOTA_TRUSTEE = 591668,

            [Description("msDS-QuotaUsed")]
            ATT_MS_DS_QUOTA_USED = 591673,

            [Description("msDS-NCReplCursors")]
            ATT_MS_DS_NC_REPL_CURSORS = 591528,

            [Description("msDS-NCReplInboundNeighbors")]
            ATT_MS_DS_NC_REPL_INBOUND_NEIGHBORS = 591529,

            [Description("msDS-NCReplOutboundNeighbors")]
            ATT_MS_DS_NC_REPL_OUTBOUND_NEIGHBORS = 591530,

            [Description("msDS-NC-Replica-Locations")]
            ATT_MS_DS_NC_REPLICA_LOCATIONS = 591485,

            [Description("msDS-NC-RO-Replica-Locations")]
            ATT_MS_DS_NC_RO_REPLICA_LOCATIONS = 591791,

            [Description("msDS-PerUserTrustQuota")]
            ATT_MS_DS_PER_USER_TRUST_QUOTA = 591612,

            [Description("msDS-PerUserTrustTombstonesQuota")]
            ATT_MS_DS_PER_USER_TRUST_TOMBSTONES_QUOTA = 591614,

            [Description("msDS-Preferred-GC-Site")]
            ATT_MS_DS_PREFERRED_GC_SITE = 591268,

            [Description("msDS-ReplAttributeMetaData")]
            ATT_MS_DS_REPL_ATTRIBUTE_META_DATA = 591531,

            [Description("msDS-ReplValueMetaData")]
            ATT_MS_DS_REPL_VALUE_META_DATA = 591532,

            [Description("mS-DS-ReplicatesNCReason")]
            ATT_MS_DS_REPLICATES_NC_REASON = 591232,

            [Description("msDS-Replication-Notify-First-DSA-Delay")]
            ATT_MS_DS_REPLICATION_NOTIFY_FIRST_DSA_DELAY = 591487,

            [Description("msDS-Replication-Notify-Subsequent-DSA-Delay")]
            ATT_MS_DS_REPLICATION_NOTIFY_SUBSEQUENT_DSA_DELAY = 591488,

            [Description("msDS-ReplicationEpoch")]
            ATT_MS_DS_REPLICATIONEPOCH = 591544,

            [Description("msDS-RetiredReplNCSignatures")]
            ATT_MS_DS_RETIRED_REPL_NC_SIGNATURES = 591650,

            [Description("msDS-SDReferenceDomain")]
            ATT_MS_DS_SD_REFERENCE_DOMAIN = 591535,

            [Description("msDS-Site-Affinity")]
            ATT_MS_DS_SITE_AFFINITY = 591267,

            [Description("msDS-SPNSuffixes")]
            ATT_MS_DS_SPN_SUFFIXES = 591539,

            [Description("msDS-UserPasswordExpiryTimeComputed")]
            ATT_MS_DS_USER_PASSWORD_EXPIRY_TIME_COMPUTED = 591820,

            [Description("msDS-User-Account-Control-Computed")]
            ATT_MS_DS_USER_ACCOUNT_CONTROL_COMPUTED = 591284,

            [Description("msDS-UpdateScript")]
            ATT_MS_DS_UPDATESCRIPT = 591545,

            [Description("msDS-KrbTgtLink")]
            ATT_MS_DS_KRBTGT_LINK = 591747,

            [Description("msDS-RevealedUsers")]
            ATT_MS_DS_REVEALED_USERS = 591748,

            [Description("msDS-hasFullReplicaNCs")]
            ATT_MS_DS_HAS_FULL_REPLICA_NCS = 591749,

            [Description("msDS-NeverRevealGroup")]
            ATT_MS_DS_NEVER_REVEAL_GROUP = 591750,

            [Description("msDS-RevealOnDemandGroup")]
            ATT_MS_DS_REVEAL_ONDEMAND_GROUP = 591752,

            [Description("msDS-SecondaryKrbTgtNumber")]
            ATT_MS_DS_SECONDARY_KRBTGT_NUMBER = 591753,

            [Description("msDS-RevealedDSAs")]
            ATT_MS_DS_REVEALED_DSAS = 591754,

            [Description("msDS-KrbTgtLinkBl")]
            ATT_MS_DS_KRBTGT_LINK_BL = 591755,

            [Description("msDS-IsUserCachableAtRodc")]
            ATT_MS_DS_IS_USER_CACHABLE_AT_RODC = 591849,

            [Description("msDS-RevealedList")]
            ATT_MS_DS_REVEALED_LIST = 591764,

            [Description("msDS-RevealedListBL")]
            ATT_MS_DS_REVEALED_LIST_BL = 591799,

            [Description("msDS-LastSuccessfulInteractiveLogonTime")]
            ATT_MS_DS_LAST_SUCCESSFUL_INTERACTIVE_LOGON_TIME = 591794,

            [Description("msDS-LastFailedInteractiveLogonTime")]
            ATT_MS_DS_LAST_FAILED_INTERACTIVE_LOGON_TIME = 591795,

            [Description("msDS-FailedInteractiveLogonCount")]
            ATT_MS_DS_FAILED_INTERACTIVE_LOGON_COUNT = 591796,

            [Description("msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon")]
            ATT_MS_DS_FAILED_INTERACTIVE_LOGON_COUNT_AT_LAST_SUCCESSFUL_LOGON = 591797,

            [Description("mSMQOwnerID")]
            ATT_MSMQ_OWNER_ID = 590749,

            [Description("mustContain")]
            ATT_MUST_CONTAIN = 131096,

            [Description("nCName")]
            ATT_NC_NAME = 131088,

            [Description("nETBIOSName")]
            ATT_NETBIOS_NAME = 589911,

            [Description("nextRid")]
            ATT_NEXT_RID = 589912,

            [Description("nTMixedDomain")]
            ATT_NT_MIXED_DOMAIN = 590181,

            [Description("ntPwdHistory")]
            ATT_NT_PWD_HISTORY = 589918,

            [Description("nTSecurityDescriptor")]
            ATT_NT_SECURITY_DESCRIPTOR = 131353,

            [Description("distinguishedName")]
            ATT_OBJ_DIST_NAME = 49,

            [Description("objectCategory")]
            ATT_OBJECT_CATEGORY = 590606,

            [Description("objectClass")]
            ATT_OBJECT_CLASS = 0,

            [Description("objectClassCategory")]
            ATT_OBJECT_CLASS_CATEGORY = 131442,

            [Description("objectClasses")]
            ATT_OBJECT_CLASSES = 1572870,

            [Description("objectGUID")]
            ATT_OBJECT_GUID = 589826,

            [Description("objectSid")]
            ATT_OBJECT_SID = 589970,

            [Description("objectVersion")]
            ATT_OBJECT_VERSION = 131148,

            [Description("oEMInformation")]
            ATT_OEM_INFORMATION = 589975,

            [Description("oMObjectClass")]
            ATT_OM_OBJECT_CLASS = 131290,

            [Description("oMSyntax")]
            ATT_OM_SYNTAX = 131303,

            [Description("operatingSystem")]
            ATT_OPERATING_SYSTEM = 590187,

            [Description("operatingSystemServicePack")]
            ATT_OPERATING_SYSTEM_SERVICE_PACK = 590189,

            [Description("operatingSystemVersion")]
            ATT_OPERATING_SYSTEM_VERSION = 590188,

            [Description("operatorCount")]
            ATT_OPERATOR_COUNT = 589968,

            [Description("options")]
            ATT_OPTIONS = 590131,

            [Description("o")]
            ATT_ORGANIZATION_NAME = 10,

            [Description("ou")]
            ATT_ORGANIZATIONAL_UNIT_NAME = 11,

            [Description("otherWellKnownObjects")]
            ATT_OTHER_WELL_KNOWN_OBJECTS = 591183,

            [Description("parentGUID")]
            ATT_PARENT_GUID = 591048,

            [Description("partialAttributeDeletionList")]
            ATT_PARTIAL_ATTRIBUTE_DELETION_LIST = 590487,

            [Description("partialAttributeSet")]
            ATT_PARTIAL_ATTRIBUTE_SET = 590464,

            [Description("pekList")]
            ATT_PEK_LIST = 590689,

            [Description("possSuperiors")]
            ATT_POSS_SUPERIORS = 131080,

            [Description("possibleInferiors")]
            ATT_POSSIBLE_INFERIORS = 590739,

            [Description("prefixMap")]
            ATT_PREFIX_MAP = 590362,

            [Description("primaryGroupID")]
            ATT_PRIMARY_GROUP_ID = 589922,

            [Description("primaryGroupToken")]
            ATT_PRIMARY_GROUP_TOKEN = 591236,

            [Description("priorSetTime")]
            ATT_PRIOR_SET_TIME = 589923,

            [Description("priorValue")]
            ATT_PRIOR_VALUE = 589924,

            [Description("privateKey")]
            ATT_PRIVATE_KEY = 589925,

            [Description("profilePath")]
            ATT_PROFILE_PATH = 589963,

            [Description("proxiedObjectName")]
            ATT_PROXIED_OBJECT_NAME = 591073,

            [Description("proxyAddresses")]
            ATT_PROXY_ADDRESSES = 131282,

            [Description("proxyLifetime")]
            ATT_PROXY_LIFETIME = 589927,

            [Description("pwdHistoryLength")]
            ATT_PWD_HISTORY_LENGTH = 589919,

            [Description("pwdLastSet")]
            ATT_PWD_LAST_SET = 589920,

            [Description("pwdProperties")]
            ATT_PWD_PROPERTIES = 589917,

            [Description("queryPolicyObject")]
            ATT_QUERY_POLICY_OBJECT = 590431,

            [Description("rangeLower")]
            ATT_RANGE_LOWER = 131106,

            [Description("rangeUpper")]
            ATT_RANGE_UPPER = 131107,

            [Description("name")]
            ATT_RDN = 589825,

            [Description("rDNAttID")]
            ATT_RDN_ATT_ID = 131098,

            [Description("replPropertyMetaData")]
            ATT_REPL_PROPERTY_META_DATA = 589827,

            [Description("replTopologyStayOfExecution")]
            ATT_REPL_TOPOLOGY_STAY_OF_EXECUTION = 590501,

            [Description("replUpToDateVector")]
            ATT_REPL_UPTODATE_VECTOR = 589828,

            [Description("replInterval")]
            ATT_REPL_INTERVAL = 591160,

            [Description("repsFrom")]
            ATT_REPS_FROM = 131163,

            [Description("repsTo")]
            ATT_REPS_TO = 131155,

            [Description("retiredReplDSASignatures")]
            ATT_RETIRED_REPL_DSA_SIGNATURES = 590497,

            [Description("tokenGroups")]
            ATT_TOKEN_GROUPS = 591125,

            [Description("tokenGroupsGlobalAndUniversal")]
            ATT_TOKEN_GROUPS_GLOBAL_AND_UNIVERSAL = 591242,

            [Description("tokenGroupsNoGCAcceptable")]
            ATT_TOKEN_GROUPS_NO_GC_ACCEPTABLE = 591127,

            [Description("revision")]
            ATT_REVISION = 589969,

            [Description("rid")]
            ATT_RID = 589977,

            [Description("rIDAllocationPool")]
            ATT_RID_ALLOCATION_POOL = 590195,

            [Description("rIDAvailablePool")]
            ATT_RID_AVAILABLE_POOL = 590194,

            [Description("rIDManagerReference")]
            ATT_RID_MANAGER_REFERENCE = 590192,

            [Description("rIDNextRID")]
            ATT_RID_NEXT_RID = 590198,

            [Description("rIDPreviousAllocationPool")]
            ATT_RID_PREVIOUS_ALLOCATION_POOL = 590196,

            [Description("rIDSetReferences")]
            ATT_RID_SET_REFERENCES = 590493,

            [Description("rIDUsedPool")]
            ATT_RID_USED_POOL = 590197,

            [Description("rightsGuid")]
            ATT_RIGHTS_GUID = 590164,

            [Description("rootTrust")]
            ATT_ROOT_TRUST = 590498,

            [Description("sAMAccountName")]
            ATT_SAM_ACCOUNT_NAME = 590045,

            [Description("sAMAccountType")]
            ATT_SAM_ACCOUNT_TYPE = 590126,

            [Description("samDomainUpdates")]
            ATT_SAM_DOMAIN_UPDATES = 591793,

            [Description("schedule")]
            ATT_SCHEDULE = 590035,

            [Description("schemaIDGUID")]
            ATT_SCHEMA_ID_GUID = 589972,

            [Description("schemaInfo")]
            ATT_SCHEMA_INFO = 591182,

            [Description("scriptPath")]
            ATT_SCRIPT_PATH = 589886,

            [Description("sDRightsEffective")]
            ATT_SD_RIGHTS_EFFECTIVE = 591128,

            [Description("searchFlags")]
            ATT_SEARCH_FLAGS = 131406,

            [Description("securityIdentifier")]
            ATT_SECURITY_IDENTIFIER = 589945,

            [Description("serverName")]
            ATT_SERVER_NAME = 590047,

            [Description("serverReference")]
            ATT_SERVER_REFERENCE = 590339,

            [Description("serverReferenceBL")]
            ATT_SERVER_REFERENCE_BL = 590340,

            [Description("serverState")]
            ATT_SERVER_STATE = 589978,

            [Description("servicePrincipalName")]
            ATT_SERVICE_PRINCIPAL_NAME = 590595,

            [Description("showInAddressBook")]
            ATT_SHOW_IN_ADDRESS_BOOK = 590468,

            [Description("showInAdvancedViewOnly")]
            ATT_SHOW_IN_ADVANCED_VIEW_ONLY = 131241,

            [Description("sIDHistory")]
            ATT_SID_HISTORY = 590433,

            [Description("siteLinkList")]
            ATT_SITE_LINK_LIST = 590646,

            [Description("siteList")]
            ATT_SITE_LIST = 590645,

            [Description("siteObject")]
            ATT_SITE_OBJECT = 590336,

            [Description("mailAddress")]
            ATT_SMTP_MAIL_ADDRESS = 590610,

            [Description("sPNMappings")]
            ATT_SPN_MAPPINGS = 591171,

            [Description("st")]
            ATT_STATE_OR_PROVINCE_NAME = 8,

            [Description("street")]
            ATT_STREET_ADDRESS = 9,

            [Description("structuralObjectClass")]
            ATT_STRUCTURAL_OBJECT_CLASS = 1572873,

            [Description("subClassOf")]
            ATT_SUB_CLASS_OF = 131093,

            [Description("subRefs")]
            ATT_SUB_REFS = 131079,

            [Description("subSchemaSubEntry")]
            ATT_SUBSCHEMASUBENTRY = 1638410,

            [Description("superiorDNSRoot")]
            ATT_SUPERIOR_DNS_ROOT = 590356,

            [Description("supplementalCredentials")]
            ATT_SUPPLEMENTAL_CREDENTIALS = 589949,

            [Description("sn")]
            ATT_SURNAME = 4,

            [Description("systemAuxiliaryClass")]
            ATT_SYSTEM_AUXILIARY_CLASS = 590022,

            [Description("systemFlags")]
            ATT_SYSTEM_FLAGS = 590199,

            [Description("systemMayContain")]
            ATT_SYSTEM_MAY_CONTAIN = 590020,

            [Description("systemMustContain")]
            ATT_SYSTEM_MUST_CONTAIN = 590021,

            [Description("systemOnly")]
            ATT_SYSTEM_ONLY = 589994,

            [Description("systemPossSuperiors")]
            ATT_SYSTEM_POSS_SUPERIORS = 590019,

            [Description("templateRoots")]
            ATT_TEMPLATE_ROOTS = 591170,

            [Description("tombstoneLifetime")]
            ATT_TOMBSTONE_LIFETIME = 131126,

            [Description("transportAddressAttribute")]
            ATT_TRANSPORT_ADDRESS_ATTRIBUTE = 590719,

            [Description("transportDLLName")]
            ATT_TRANSPORT_DLL_NAME = 590613,

            [Description("transportType")]
            ATT_TRANSPORT_TYPE = 590615,

            [Description("trustAttributes")]
            ATT_TRUST_ATTRIBUTES = 590294,

            [Description("trustAuthIncoming")]
            ATT_TRUST_AUTH_INCOMING = 589953,

            [Description("trustAuthOutgoing")]
            ATT_TRUST_AUTH_OUTGOING = 589959,

            [Description("trustDirection")]
            ATT_TRUST_DIRECTION = 589956,

            [Description("trustParent")]
            ATT_TRUST_PARENT = 590295,

            [Description("trustPartner")]
            ATT_TRUST_PARTNER = 589957,

            [Description("trustPosixOffset")]
            ATT_TRUST_POSIX_OFFSET = 589958,

            [Description("trustType")]
            ATT_TRUST_TYPE = 589960,

            [Description("uASCompat")]
            ATT_UAS_COMPAT = 589979,

            [Description("unicodePwd")]
            ATT_UNICODE_PWD = 589914,

            [Description("uPNSuffixes")]
            ATT_UPN_SUFFIXES = 590714,

            [Description("userAccountControl")]
            ATT_USER_ACCOUNT_CONTROL = 589832,

            [Description("comment")]
            ATT_USER_COMMENT = 589980,

            [Description("userParameters")]
            ATT_USER_PARAMETERS = 589962,

            [Description("userPassword")]
            ATT_USER_PASSWORD = 35,

            [Description("userPrincipalName")]
            ATT_USER_PRINCIPAL_NAME = 590480,

            [Description("userWorkstations")]
            ATT_USER_WORKSTATIONS = 589910,

            [Description("uSNChanged")]
            ATT_USN_CHANGED = 131192,

            [Description("uSNCreated")]
            ATT_USN_CREATED = 131091,

            [Description("uSNDSALastObjRemoved")]
            ATT_USN_DSA_LAST_OBJ_REMOVED = 131339,

            [Description("uSNLastObjRem")]
            ATT_USN_LAST_OBJ_REM = 131193,

            [Description("validAccesses")]
            ATT_VALID_ACCESSES = 591180,

            [Description("wellKnownObjects")]
            ATT_WELL_KNOWN_OBJECTS = 590442,

            [Description("whenChanged")]
            ATT_WHEN_CHANGED = 131075,

            [Description("whenCreated")]
            ATT_WHEN_CREATED = 131074,

            [Description("schemaFlagsEx")]
            ATT_SCHEMA_FLAGS_EX = 589944,

            [Description("msDFS-SchemaMajorVersion")]
            ATT_MS_DFS_SCHEMA_MAJOR_VERSION = 591854,

            [Description("msDFS-SchemaMinorVersion")]
            ATT_MS_DFS_SCHEMA_MINOR_VERSION = 591855,

            [Description("msDFS-GenerationGUIDv2")]
            ATT_MS_DFS_GENERATION_GUID_V2 = 591856,

            [Description("msDFS-NamespaceIdentityGUIDv2")]
            ATT_MS_DFS_NAMESPACE_IDENTITY_GUID_V2 = 591857,

            [Description("msDFS-LastModifiedv2")]
            ATT_MS_DFS_LAST_MODIFIED_V2 = 591858,

            [Description("msDFS-Ttlv2")]
            ATT_MS_DFS_TTL_V2 = 591859,

            [Description("msDFS-Commentv2")]
            ATT_MS_DFS_COMMENT_V2 = 591860,

            [Description("msDFS-Propertiesv2")]
            ATT_MS_DFS_PROPERTIES_V2 = 591861,

            [Description("msDFS-TargetListv2")]
            ATT_MS_DFS_TARGET_LIST_V2 = 591862,

            [Description("msDFS-LinkPathv2")]
            ATT_MS_DFS_LINK_PATH_V2 = 591863,

            [Description("msDFS-LinkSecurityDescriptorv2")]
            ATT_MS_DFS_LINK_SECURITY_DESCRIPTOR_V2 = 591864,

            [Description("msDFS-LinkIdentityGUIDv2")]
            ATT_MS_DFS_LINK_IDENTITY_GUID_V2 = 591865,

            [Description("msDFS-ShortNameLinkPathv2")]
            ATT_MS_DFS_SHORT_NAME_LINK_PATH_V2 = 591866,

            [Description("addressBookRoots2")]
            ATT_ADDRESS_BOOK_ROOTS2 = 591870,

            [Description("templateRoots2")]
            ATT_TEMPLATE_ROOTS2 = 591872,

            [Description("msTSExpireDate")]
            ATT_MS_TS_EXPIREDATE = 591817,

            [Description("globalAddressList2")]
            ATT_GLOBAL_ADDRESS_LIST2 = 591871,

            [Description("msDS-BridgeHeadServersUsed")]
            ATT_MS_DS_BRIDGEHEAD_SERVERS_USED = 591873,

            [Description("msDS-HABSeniorityIndex")]
            ATT_MS_DS_HAB_SENIORITY_INDEX = 591821,

            [Description("msFVE-VolumeGuid")]
            ATT_MS_FVE_VOLUMEGUID = 591822,

            [Description("msFVE-RecoveryGuid")]
            ATT_MS_FVE_RECOVERYGUID = 591789,

            [Description("lastLogonTimestamp")]
            ATT_LAST_LOGON_TIMESTAMP = 591520,

            [Description("msPKIDPAPIMasterKeys")]
            ATT_MS_PKI_DPAPIMASTERKEYS = 591717,

            [Description("msPKIAccountCredentials")]
            ATT_MS_PKI_ACCOUNTCREDENTIALS = 591718,

            [Description("msPKIRoamingTimeStamp")]
            ATT_MS_PKI_ROAMINGTIMESTAMP = 591716,

            [Description("mSSMSHealthState")]
            ATT_MS_SMS_HEALTH_STATE = 1844510731,

            [Description("mSSMSSourceForest")]
            ATT_MS_SMS_SOURCE_FOREST = 1844510732,

            [Description("mSSMSVersion")]
            ATT_MS_SMS_VERSION = 1844510735,

            [Description("mSSMSCapabilities")]
            ATT_MS_SMS_CAPABILITIES = 1844510734,

            [Description("msDS-USNLastSyncSuccess")]
            ATT_MS_DS_USN_LAST_SYNC_SUCCESS = 591879,

            [Description("isRecycled")]
            ATT_IS_RECYCLED = 591882,

            [Description("msDS-OptionalFeatureGUID")]
            ATT_MS_DS_OPTIONAL_FEATURE_GUID = 591886,

            [Description("msDS-EnabledFeature")]
            ATT_MS_DS_ENABLED_FEATURE = 591885,

            [Description("msImaging-PSPString")]
            ATT_MS_IMAGING_PSP_STRING = 591878,

            [Description("msDS-OIDToGroupLink")]
            ATT_MS_DS_OIDTOGROUP_LINK = 591875,

            [Description("msDS-OIDToGroupLinkBl")]
            ATT_MS_DS_OIDTOGROUP_LINK_BL = 591876,

            [Description("msImaging-PSPIdentifier")]
            ATT_MS_IMAGING_PSP_IDENTIFIER = 591877,

            [Description("msDS-HostServiceAccount")]
            ATT_MS_DS_HOST_SERVICE_ACCOUNT = 591880,

            [Description("msDS-HostServiceAccountBL")]
            ATT_MS_DS_HOST_SERVICE_ACCOUNT_BL = 591881,

            [Description("msDS-RequiredDomainBehaviorVersion")]
            ATT_MS_DS_REQUIRED_DOMAIN_BEHAVIOR_VERSION = 591890,

            [Description("msDS-RequiredForestBehaviorVersion")]
            ATT_MS_DS_REQUIRED_FOREST_BEHAVIOR_VERSION = 591903,

            [Description("msPKI-CredentialRoamingTokens")]
            ATT_MS_PKI_CREDENTIAL_ROAMING_TOKENS = 591874,

            [Description("msDS-LocalEffectiveRecycleTime")]
            ATT_MS_DS_LOCAL_EFFECTIVE_RECYCLE_TIME = 591884,

            [Description("msDS-LocalEffectiveDeletionTime")]
            ATT_MS_DS_LOCAL_EFFECTIVE_DELETION_TIME = 591883,

            [Description("msDS-LastKnownRDN")]
            ATT_MS_DS_LAST_KNOWN_RDN = 591891,

            [Description("msDS-EnabledFeatureBL")]
            ATT_MS_DS_ENABLED_FEATURE_BL = 591893,

            [Description("msDS-DeletedObjectLifetime")]
            ATT_MS_DS_DELETED_OBJECT_LIFETIME = 591892,

            [Description("msDS-OptionalFeatureFlags")]
            ATT_MS_DS_OPTIONAL_FEATURE_FLAGS = 591887,

            [Description("msPKI-Enrollment-Servers")]
            ATT_MS_PKI_ENROLLMENT_SERVERS = 591900,

            [Description("msPKI-Site-Name")]
            ATT_MS_PKI_SITE_NAME = 591901,

            [Description("msTSEndpointData")]
            ATT_MS_TS_ENDPOINT_DATA = 591894,

            [Description("msTSEndpointType")]
            ATT_MS_TS_ENDPOINT_TYPE = 591895,

            [Description("msTSEndpointPlugin")]
            ATT_MS_TS_ENDPOINT_PLUGIN = 591896,

            [Description("msTSPrimaryDesktop")]
            ATT_MS_TS_PRIMARY_DESKTOP = 591897,

            [Description("msTSSecondaryDesktops")]
            ATT_MS_TS_SECONDARY_DESKTOPS = 591899,

            [Description("msTSPrimaryDesktopBL")]
            ATT_MS_TS_PRIMARY_DESKTOP_BL = 591898,

            [Description("msTSSecondaryDesktopBL")]
            ATT_MS_TS_SECONDARY_DESKTOP_BL = 591902,

            [Description("msPKI-Cert-Template-OID")]
            ATT_MS_PKI_CERT_TEMPLATE_OID = 591260,

            [Description("msExchHABShowInDepartments")]
            ATT_MS_EXCH_HAB_SHOW_IN_DEPARTMENTS = 1030522503,

            [Description("msExchHABShowInDepartmentsBL")]
            ATT_MS_EXCH_HAB_SHOW_IN_DEPARTMENTS_BL = 1030522505,

            [Description("msExchHABRootDepartmentLink")]
            ATT_MS_EXCH_HAB_ROOT_DEPARTMENT_LINK = 1030522504,

            [Description("msExchHABRootDepartmentBL")]
            ATT_MS_EXCH_HAB_ROOT_DEPARTMENT_BL = 1030522506,

            [Description("msExchHABChildDepartmentsLink")]
            ATT_MS_EXCH_HAB_CHILD_DEPARTMENTS_LINK = 1030522507,

            [Description("msExchHABChildDepartmentsBL")]
            ATT_MS_EXCH_HAB_CHILD_DEPARTMENTS_BL = 1030522508,

            [Description("msExchActivationPreference")]
            ATT_MS_EXCH_ACTIVATION_PREFERENCE = 1030522620,

            [Description("msExchCU")]
            ATT_MS_EXCH_CU = 1030522600,

            [Description("msExchMasterServerOrAvailabilityGroup")]
            ATT_MS_EXCH_MASTER_SERVER_OR_AVAILABILITY_GROUP = 1030522597,

            [Description("msExchOURoot")]
            ATT_MS_EXCH_OU_ROOT = 1030522601,

            [Description("msExchReplayLag")]
            ATT_MS_EXCH_REPLAY_LAG = 1030522619,

            [Description("msExchRoleAssignmentFlags")]
            ATT_MS_EXCH_ROLE_ASSIGNMENT_FLAGS = 1030522625,

            [Description("msExchRoleEntries")]
            ATT_MS_EXCH_ROLE_ENTRIES = 1030522621,

            [Description("msExchRoleFlags")]
            ATT_MS_EXCH_ROLE_FLAGS = 1030522622,

            [Description("msExchScopeFlags")]
            ATT_MS_EXCH_SCOPE_FLAGS = 1030522623,

            [Description("msExchScopeRoot")]
            ATT_MS_EXCH_SCOPE_ROOT = 1030522624,

            [Description("msExchSenderHintLargeAudienceThreshold")]
            ATT_MS_EXCH_SENDER_HINT_LARGE_AUDIENCE_THRESHOLD = 1030522581,

            [Description("msExchSenderHintTranslations")]
            ATT_MS_EXCH_SENDER_HINT_TRANSLATIONS = 1030522579,

            [Description("msExchSenderHintsEnabled")]
            ATT_MS_EXCH_SENDER_HINTS_ENABLED = 1030522580,

            [Description("msExchTruncationLag")]
            ATT_MS_EXCH_TRUNCATION_LAG = 1030522618,

            [Description("msExchUMDialPlanFlags2")]
            ATT_MS_EXCH_UM_DIAL_PLAN_FLAGS_2 = 1030522586,

            [Description("msExchUMDialPlanSubscriberType")]
            ATT_MS_EXCH_UM_DIAL_PLAN_SUBSCRIBER_TYPE = 1030522583,

            [Description("msExchUMEnabledFlags2")]
            ATT_MS_EXCH_UM_ENABLED_FLAGS_2 = 1030522585,

            [Description("msExchHostServerLink")]
            ATT_MS_EXCH_HOST_SERVER_LINK = 1030522593,

            [Description("msExchHostServerBL")]
            ATT_MS_EXCH_HOST_SERVER_BL = 1030522592,

            [Description("msExchMDBAvailabilityGroupLink")]
            ATT_MS_EXCH_MDB_AVAILABILITY_GROUP_LINK = 1030522595,

            [Description("msExchMDBAvailabilityGroupBL")]
            ATT_MS_EXCH_MDB_AVAILABILITY_GROUP_BL = 1030522596,

            [Description("msExchConfigurationUnitLink")]
            ATT_MS_EXCH_CONFIGURATION_UNIT_LINK = 1030522598,

            [Description("msExchConfigurationUnitBL")]
            ATT_MS_EXCH_CONFIGURATION_UNIT_BL = 1030522599,

            [Description("msExchPolicyTagLink")]
            ATT_MS_EXCH_POLICY_TAG_LINK = 1030522616,

            [Description("msExchPolicyTagLinkBL")]
            ATT_MS_EXCH_POLICY_TAG_LINK_BL = 1030522617,

            [Description("msExchRoleLink")]
            ATT_MS_EXCH_ROLE_LINK = 1030522626,

            [Description("msExchUserLink")]
            ATT_MS_EXCH_USER_LINK = 1030522627,

            [Description("msExchDomainRestrictionLink")]
            ATT_MS_EXCH_DOMAIN_RESTRICTION_LINK = 1030522628,

            [Description("msExchConfigRestrictionLink")]
            ATT_MS_EXCH_CONFIG_RESTRICTION_LINK = 1030522629,

            [Description("msExchArbitrationMailbox")]
            ATT_MS_EXCH_ARBITRATION_MAILBOX = 1030522637,

            [Description("msExchBlockedSendersHash")]
            ATT_MS_EXCH_BLOCKED_SENDERS_HASH = 1030522656,

            [Description("msExchCustomerFeedbackEnabled")]
            ATT_MS_EXCH_CUSTOMER_FEEDBACK_ENABLED = 1030522661,

            [Description("msExchCustomerFeedbackURL")]
            ATT_MS_EXCH_CUSTOMER_FEEDBACK_URL = 1030522677,

            [Description("msExchDeviceFriendlyName")]
            ATT_MS_EXCH_DEVICE_FRIENDLY_NAME = 1030522610,

            [Description("msExchDeviceHealth")]
            ATT_MS_EXCH_DEVICE_HEALTH = 1030522614,

            [Description("msExchDeviceID")]
            ATT_MS_EXCH_DEVICE_ID = 1030522602,

            [Description("msExchDeviceIMEI")]
            ATT_MS_EXCH_DEVICE_IMEI = 1030522606,

            [Description("msExchDeviceMobileOperator")]
            ATT_MS_EXCH_DEVICE_MOBILE_OPERATOR = 1030522611,

            [Description("msExchDeviceOS")]
            ATT_MS_EXCH_DEVICE_OS = 1030522607,

            [Description("msExchDeviceOSLanguage")]
            ATT_MS_EXCH_DEVICE_OS_LANGUAGE = 1030522608,

            [Description("msExchDeviceTelephoneNumber")]
            ATT_MS_EXCH_DEVICE_TELEPHONE_NUMBER = 1030522609,

            [Description("msExchDeviceType")]
            ATT_MS_EXCH_DEVICE_TYPE = 1030522603,

            [Description("msExchDeviceUserAgent")]
            ATT_MS_EXCH_DEVICE_USER_AGENT = 1030522605,

            [Description("msExchDistributionListCountQuota")]
            ATT_MS_EXCH_DISTRIBUTION_LIST_COUNT_QUOTA = 1030522688,

            [Description("msExchDistributionListOU")]
            ATT_MS_EXCH_DISTRIBUTION_LIST_OU = 1030522695,

            [Description("msExchEdgeSyncCookies")]
            ATT_MS_EXCH_EDGE_SYNC_COOKIES = 1030522640,

            [Description("msExchEdgeSyncSourceGuid")]
            ATT_MS_EXCH_EDGE_SYNC_SOURCE_GUID = 1030522642,

            [Description("msExchEnableModeration")]
            ATT_MS_EXCH_ENABLE_MODERATION = 1030522649,

            [Description("msExchFileShareWitness")]
            ATT_MS_EXCH_FILE_SHARE_WITNESS = 1030522658,

            [Description("msExchFileShareWitnessDirectory")]
            ATT_MS_EXCH_FILE_SHARE_WITNESS_DIRECTORY = 1030522659,

            [Description("msExchFirstSyncTime")]
            ATT_MS_EXCH_FIRST_SYNC_TIME = 1030522612,

            [Description("msExchGroupDepartRestriction")]
            ATT_MS_EXCH_GROUP_DEPART_RESTRICTION = 1030522644,

            [Description("msExchGroupJoinRestriction")]
            ATT_MS_EXCH_GROUP_JOIN_RESTRICTION = 1030522643,

            [Description("msExchIndustry")]
            ATT_MS_EXCH_INDUSTRY = 1030522676,

            [Description("msExchLastUpdateTime")]
            ATT_MS_EXCH_LAST_UPDATE_TIME = 1030522613,

            [Description("msExchMaxSignupAddressesPerUser")]
            ATT_MS_EXCH_MAX_SIGNUP_ADDRESSES_PER_USER = 1030522672,

            [Description("msExchMDBAvailabilityGroupName")]
            ATT_MS_EXCH_MDB_AVAILABILITY_GROUP_NAME = 1030522660,

            [Description("msExchMessageHygieneRecipientBlockedSenderAction")]
            ATT_MS_EXCH_MESSAGE_HYGIENE_RECIPIENT_BLOCKED_SENDER_ACTION = 1030522655,

            [Description("msExchModerationFlags")]
            ATT_MS_EXCH_MODERATION_FLAGS = 1030522652,

            [Description("msExchOABANRProperties")]
            ATT_MS_EXCH_OAB_ANR_PROPERTIES = 1030522682,

            [Description("msExchOABDetailsProperties")]
            ATT_MS_EXCH_OAB_DETAILS_PROPERTIES = 1030522683,

            [Description("msExchOABMaxBinarySize")]
            ATT_MS_EXCH_OAB_MAX_BINARY_SIZE = 1030522678,

            [Description("msExchOABMaxMVBinarySize")]
            ATT_MS_EXCH_OAB_MAX_MV_BINARY_SIZE = 1030522679,

            [Description("msExchOABMaxMVStringSize")]
            ATT_MS_EXCH_OAB_MAX_MV_STRING_SIZE = 1030522681,

            [Description("msExchOABMaxStringSize")]
            ATT_MS_EXCH_OAB_MAX_STRING_SIZE = 1030522680,

            [Description("msExchOABTruncatedProperties")]
            ATT_MS_EXCH_OAB_TRUNCATED_PROPERTIES = 1030522684,

            [Description("msExchOWAPolicy")]
            ATT_MS_EXCH_OWA_POLICY = 1030522673,

            [Description("msExchPopImapProtocolFlags")]
            ATT_MS_EXCH_POP_IMAP_PROTOCOL_FLAGS = 1030522674,

            [Description("msExchProvisioningPolicyScopeLinks")]
            ATT_MS_EXCH_PROVISIONING_POLICY_SCOPE_LINKS = 1030522698,

            [Description("msExchProvisioningPolicyTargetObjects")]
            ATT_MS_EXCH_PROVISIONING_POLICY_TARGET_OBJECTS = 1030522697,

            [Description("msExchProvisioningPolicyType")]
            ATT_MS_EXCH_PROVISIONING_POLICY_TYPE = 1030522699,

            [Description("msExchRecipientIssueWarningQuota")]
            ATT_MS_EXCH_RECIPIENT_ISSUE_WARNING_QUOTA = 1030522689,

            [Description("msExchRecipientMaxReceiveSize")]
            ATT_MS_EXCH_RECIPIENT_MAX_RECEIVE_SIZE = 1030522690,

            [Description("msExchRecipientMaxSendSize")]
            ATT_MS_EXCH_RECIPIENT_MAX_SEND_SIZE = 1030522691,

            [Description("msExchRecipientProhibitSendQuota")]
            ATT_MS_EXCH_RECIPIENT_PROHIBIT_SEND_QUOTA = 1030522692,

            [Description("msExchRecipientProhibitSendReceiveQuota")]
            ATT_MS_EXCH_RECIPIENT_PROHIBIT_SEND_RECEIVE_QUOTA = 1030522693,

            [Description("msExchRecipientRulesQuota")]
            ATT_MS_EXCH_RECIPIENT_RULES_QUOTA = 1030522694,

            [Description("msExchRecipientValidatorCookies")]
            ATT_MS_EXCH_RECIPIENT_VALIDATOR_COOKIES = 1030522641,

            [Description("msExchRetentionPolicyTag")]
            ATT_MS_EXCH_RETENTION_POLICY_TAG = 1030522636,

            [Description("msExchSignupAddresses")]
            ATT_MS_EXCH_SIGNUP_ADDRESSES = 1030522670,

            [Description("msExchSignupAddressesEnabled")]
            ATT_MS_EXCH_SIGNUP_ADDRESSES_ENABLED = 1030522671,

            [Description("msExchUserDisplayName")]
            ATT_MS_EXCH_USER_DISPLAY_NAME = 1030522604,

            [Description("msExchWindowsLiveID")]
            ATT_MS_EXCH_WINDOWS_LIVE_ID = 1030522696,

            [Description("msExchApprovalApplicationLink")]
            ATT_MS_EXCH_APPROVAL_APPLICATION_LINK = 1030522630,

            [Description("msExchArbitrationMailboxesBL")]
            ATT_MS_EXCH_ARBITRATION_MAILBOXES_BL = 1030522631,

            [Description("msExchCoManagedByLink")]
            ATT_MS_EXCH_CO_MANAGED_BY_LINK = 1030522633,

            [Description("msExchCoManagedObjectsBL")]
            ATT_MS_EXCH_CO_MANAGED_OBJECTS_BL = 1030522634,

            [Description("msExchModeratedByLink")]
            ATT_MS_EXCH_MODERATED_BY_LINK = 1030522632,

            [Description("msExchModeratedObjectsBL")]
            ATT_MS_EXCH_MODERATED_OBJECTS_BL = 1030522635,

            [Description("msExchOrganizationsGlobalAddressListsLink")]
            ATT_MS_EXCH_ORGANIZATIONS_GLOBAL_ADDRESS_LISTS_LINK = 1030522685,

            [Description("msExchOrganizationsAddressBookRootsLink")]
            ATT_MS_EXCH_ORGANIZATIONS_ADDRESS_BOOK_ROOTS_LINK = 1030522686,

            [Description("msExchOrganizationsTemplateRootsLink")]
            ATT_MS_EXCH_ORGANIZATIONS_TEMPLATE_ROOTS_LINK = 1030522687,

            [Description("msExchCIMDBExclusionList")]
            ATT_MS_EXCH_CI_MDB_EXCLUSION_LIST = 1030522675,

            [Description("msExchControlPanelFeedbackEnabled")]
            ATT_MS_EXCH_CONTROL_PANEL_FEEDBACK_ENABLED = 1030522706,

            [Description("msExchControlPanelFeedbackURL")]
            ATT_MS_EXCH_CONTROL_PANEL_FEEDBACK_URL = 1030522664,

            [Description("msExchControlPanelHelpURL")]
            ATT_MS_EXCH_CONTROL_PANEL_HELP_URL = 1030522663,

            [Description("msExchExchangeHelpAppOnline")]
            ATT_MS_EXCH_EXCHANGE_HELP_APP_ONLINE = 1030522662,

            [Description("msExchImmutableId")]
            ATT_MS_EXCH_IMMUTABLE_ID = 1030522702,

            [Description("msExchManagementConsoleFeedbackEnabled")]
            ATT_MS_EXCH_MANAGEMENT_CONSOLE_FEEDBACK_ENABLED = 1030522707,

            [Description("msExchManagementConsoleFeedbackURL")]
            ATT_MS_EXCH_MANAGEMENT_CONSOLE_FEEDBACK_URL = 1030522666,

            [Description("msExchManagementConsoleHelpURL")]
            ATT_MS_EXCH_MANAGEMENT_CONSOLE_HELP_URL = 1030522665,

            [Description("msExchOWAFeedbackEnabled")]
            ATT_MS_EXCH_OWA_FEEDBACK_ENABLED = 1030522708,

            [Description("msExchOWAFeedbackURL")]
            ATT_MS_EXCH_OWA_FEEDBACK_URL = 1030522668,

            [Description("msExchOWAHelpURL")]
            ATT_MS_EXCH_OWA_HELP_URL = 1030522667,

            [Description("msExchPrivacyStatementURL")]
            ATT_MS_EXCH_PRIVACY_STATEMENT_URL = 1030522700,

            [Description("msExchPrivacyStatementURLEnabled")]
            ATT_MS_EXCH_PRIVACY_STATEMENT_URL_ENABLED = 1030522710,

            [Description("msExchSharingPartnerIdentities")]
            ATT_MS_EXCH_SHARING_PARTNER_IDENTITIES = 1030522711,

            [Description("msExchTransportRecipientSettingsFlags")]
            ATT_MS_EXCH_TRANSPORT_RECIPIENT_SETTINGS_FLAGS = 1030522705,

            [Description("msExchWindowsLiveAccountURL")]
            ATT_MS_EXCH_WINDOWS_LIVE_ACCOUNT_URL = 1030522669,

            [Description("msExchWindowsLiveAccountURLEnabled")]
            ATT_MS_EXCH_WINDOWS_LIVE_ACCOUNT_URL_ENABLED = 1030522709,

            [Description("msExchOrganizationSummary")]
            ATT_MS_EXCH_ORGANIZATION_SUMMARY = 1030522703,

            [Description("msExchExternalSyncState")]
            ATT_MS_EXCH_EXTERNAL_SYNC_STATE = 1030522712,

            [Description("msExchPartnerId")]
            ATT_MS_EXCH_PARTNER_ID = 1030522713,

            [Description("msExchExcludedMailboxDatabases")]
            ATT_MS_EXCH_EXCLUDED_MAILBOX_DATABASES = 1030522714,

            [Description("msExchIncludedMailboxDatabases")]
            ATT_MS_EXCH_INCLUDED_MAILBOX_DATABASES = 1030522715,

            [Description("msExchUseExcludedMailboxDatabases")]
            ATT_MS_EXCH_USE_EXCLUDED_MAILBOX_DATABASES = 1030522716,

            [Description("msExchUseIncludedMailboxDatabases")]
            ATT_MS_EXCH_USE_INCLUDED_MAILBOX_DATABASES = 1030522717,

            [Description("msExchDeviceModel")]
            ATT_MS_EXCH_DEVICE_MODEL = 1030522718,

            [Description("msExchBlockedClientVersions")]
            ATT_MS_EXCH_BLOCKED_CLIENT_VERSIONS = 1030522729,

            [Description("msExchEncryptionRequired")]
            ATT_MS_EXCH_ENCRYPTION_REQUIRED = 1030522728,

            [Description("msExchMailTipsSettings")]
            ATT_MS_EXCH_MAILTIPS_SETTINGS = 1030522731,

            [Description("msExchOWALightFeedbackEnabled")]
            ATT_MS_EXCH_OWA_LIGHT_FEEDBACK_ENABLED = 1030522737,

            [Description("msExchOWALightFeedbackURL")]
            ATT_MS_EXCH_OWA_LIGHT_FEEDBACK_URL = 1030522738,

            [Description("msExchOWALightHelpURL")]
            ATT_MS_EXCH_OWA_LIGHT_HELP_URL = 1030522736,

            [Description("msExchSetupStatus")]
            ATT_MS_EXCH_SETUP_STATUS = 1030522741,

            [Description("msExchRoleBL")]
            ATT_MS_EXCH_ROLE_BL = 1030522733,

            [Description("msExchDomainRestrictionBL")]
            ATT_MS_EXCH_DOMAIN_RESTRICTION_BL = 1030522735,

            [Description("msExchConfigRestrictionBL")]
            ATT_MS_EXCH_CONFIG_RESTRICTION_BL = 1030522734,

            [Description("msExchExchangeRPCServiceArrayLink")]
            ATT_MS_EXCH_EXCHANGE_RPC_SERVICE_ARRAY_LINK = 1030522730,

            [Description("msExchExchangeRPCServiceArrayBL")]
            ATT_MS_EXCH_EXCHANGE_RPC_SERVICE_ARRAY_BL = 1030522742,

            [Description("msExchAllowHeuristicADCallingLineIdResolution")]
            ATT_MS_EXCH_ALLOW_HEURISTIC_AD_CALLING_LINE_ID_RESOLUTION = 1030522827,

            [Description("msExchSystemAddressList")]
            ATT_MS_EXCH_SYSTEM_ADDRESS_LIST = 1030522828,

            [Description("msExchUMCallingLineIDFormats")]
            ATT_MS_EXCH_UM_CALLING_LINE_ID_FORMATS = 1030522826,

            [Description("msExchUMCallingLineIDs")]
            ATT_MS_EXCH_UM_CALLING_LINE_IDS = 1030522825,

            [Description("msExchUMEquivalentDialPlanPhoneContexts")]
            ATT_MS_EXCH_UM_EQUIVALENT_DIAL_PLAN_PHONE_CONTEXTS = 1030522824,

            [Description("msExchUMProtectAuthenticatedVoiceMail")]
            ATT_MS_EXCH_UM_PROTECT_AUTHENTICATED_VOICE_MAIL = 1030522744,

            [Description("msExchUMProtectUnauthenticatedVoiceMail")]
            ATT_MS_EXCH_UM_PROTECT_UNAUTHENTICATED_VOICE_MAIL = 1030522743,

            [Description("msExchUMProtectedVoiceMailText")]
            ATT_MS_EXCH_UM_PROTECTED_VOICE_MAIL_TEXT = 1030522746,

            [Description("msExchUMRequireProtectedPlayOnPhone")]
            ATT_MS_EXCH_UM_REQUIRE_PROTECTED_PLAY_ON_PHONE = 1030522745,

            [Description("msExchAggregationSubscriptionCredential")]
            ATT_MS_EXCH_AGGREGATION_SUBSCRIPTION_CREDENTIAL = 1030522829,

            [Description("msExchAssembly")]
            ATT_MS_EXCH_ASSEMBLY = 1030522817,

            [Description("msExchClassFactory")]
            ATT_MS_EXCH_CLASS_FACTORY = 1030522818,

            [Description("msExchCmdletExtensionFlags")]
            ATT_MS_EXCH_CMDLET_EXTENSION_FLAGS = 1030522819,

            [Description("msExchEASThrottlingPolicyState")]
            ATT_MS_EXCH_EAS_THROTTLING_POLICY_STATE = 1030522835,

            [Description("msExchEWSThrottlingPolicyState")]
            ATT_MS_EXCH_EWS_THROTTLING_POLICY_STATE = 1030522836,

            [Description("msExchGeneralThrottlingPolicyState")]
            ATT_MS_EXCH_GENERAL_THROTTLING_POLICY_STATE = 1030522842,

            [Description("msExchIMAPThrottlingPolicyState")]
            ATT_MS_EXCH_IMAP_THROTTLING_POLICY_STATE = 1030522837,

            [Description("msExchOWAThrottlingPolicyState")]
            ATT_MS_EXCH_OWA_THROTTLING_POLICY_STATE = 1030522838,

            [Description("msExchPOPThrottlingPolicyState")]
            ATT_MS_EXCH_POP_THROTTLING_POLICY_STATE = 1030522839,

            [Description("msExchPowershellThrottlingPolicyState")]
            ATT_MS_EXCH_POWERSHELL_THROTTLING_POLICY_STATE = 1030522840,

            [Description("msExchProvisioningFlags")]
            ATT_MS_EXCH_PROVISIONING_FLAGS = 1030522823,

            [Description("msExchSendAsAddresses")]
            ATT_MS_EXCH_SEND_AS_ADDRESSES = 1030522830,

            [Description("msExchSmtpReceiveMaxAcknowledgementDelay")]
            ATT_MS_EXCH_SMTP_RECEIVE_MAX_ACKNOWLEDGEMENT_DELAY = 1030522843,

            [Description("msExchThrottlingIsDefaultPolicy")]
            ATT_MS_EXCH_THROTTLING_IS_DEFAULT_POLICY = 1030522751,

            [Description("msExchThrottlingPolicyDN")]
            ATT_MS_EXCH_THROTTLING_POLICY_DN = 1030522776,

            [Description("msExchTransportDeliveryAgentDeliveryProtocol")]
            ATT_MS_EXCH_TRANSPORT_DELIVERY_AGENT_DELIVERY_PROTOCOL = 1030522848,

            [Description("msExchTransportDeliveryAgentMaxConcurrentConnections")]
            ATT_MS_EXCH_TRANSPORT_DELIVERY_AGENT_MAX_CONCURRENT_CONNECTIONS = 1030522850,

            [Description("msExchTransportDeliveryAgentMaxMessagesPerConnection")]
            ATT_MS_EXCH_TRANSPORT_DELIVERY_AGENT_MAX_MESSAGES_PER_CONNECTION = 1030522849,

            [Description("msExchTransportShadowHeartbeatRetryCount")]
            ATT_MS_EXCH_TRANSPORT_SHADOW_HEARTBEAT_RETRY_COUNT = 1030522847,

            [Description("msExchTransportShadowHeartbeatTimeoutInterval")]
            ATT_MS_EXCH_TRANSPORT_SHADOW_HEARTBEAT_TIMEOUT_INTERVAL = 1030522846,

            [Description("msExchTransportShadowMessageAutoDiscardInterval")]
            ATT_MS_EXCH_TRANSPORT_SHADOW_MESSAGE_AUTODISCARD_INTERVAL = 1030522845,

            [Description("msExchUMRedirectTarget")]
            ATT_MS_EXCH_UM_REDIRECT_TARGET = 1030522834,

            [Description("msExchUMThrottlingPolicyState")]
            ATT_MS_EXCH_UM_THROTTLING_POLICY_STATE = 1030522841,

            [Description("msExchParentPlanLink")]
            ATT_MS_EXCH_PARENT_PLAN_LINK = 1030522822,

            [Description("msExchBypassModerationLink")]
            ATT_MS_EXCH_BYPASS_MODERATION_LINK = 1030522820,

            [Description("msExchBypassModerationBL")]
            ATT_MS_EXCH_BYPASS_MODERATION_BL = 1030522832,

            [Description("msExchBypassModerationFromDLMembersLink")]
            ATT_MS_EXCH_BYPASS_MODERATION_FROM_DL_MEMBERS_LINK = 1030522821,

            [Description("msExchBypassModerationFromDLMembersBL")]
            ATT_MS_EXCH_BYPASS_MODERATION_FROM_DL_MEMBERS_BL = 1030522831,

            [Description("msExchEdgeSyncConfigurationSyncInterval")]
            ATT_MS_EXCH_EDGE_SYNC_CONFIGURATION_SYNC_INTERVAL = 1030522851,

            [Description("msExchEdgeSyncCookieValidDuration")]
            ATT_MS_EXCH_EDGE_SYNC_COOKIE_VALID_DURATION = 1030522856,

            [Description("msExchEdgeSyncFailoverDCInterval")]
            ATT_MS_EXCH_EDGE_SYNC_FAILOVER_DC_INTERVAL = 1030522857,

            [Description("msExchEdgeSyncLockDuration")]
            ATT_MS_EXCH_EDGE_SYNC_LOCK_DURATION = 1030522853,

            [Description("msExchEdgeSyncLockRenewalDuration")]
            ATT_MS_EXCH_EDGE_SYNC_LOCK_RENEWAL_DURATION = 1030522854,

            [Description("msExchEdgeSyncLogEnabled")]
            ATT_MS_EXCH_EDGE_SYNC_LOG_ENABLED = 1030522858,

            [Description("msExchEdgeSyncLogLevel")]
            ATT_MS_EXCH_EDGE_SYNC_LOG_LEVEL = 1030522862,

            [Description("msExchEdgeSyncLogMaxAge")]
            ATT_MS_EXCH_EDGE_SYNC_LOG_MAX_AGE = 1030522859,

            [Description("msExchEdgeSyncLogMaxDirectorySize")]
            ATT_MS_EXCH_EDGE_SYNC_LOG_MAX_DIRECTORY_SIZE = 1030522860,

            [Description("msExchEdgeSyncLogMaxFileSize")]
            ATT_MS_EXCH_EDGE_SYNC_LOG_MAX_FILE_SIZE = 1030522861,

            [Description("msExchEdgeSyncLogPath")]
            ATT_MS_EXCH_EDGE_SYNC_LOG_PATH = 1030522863,

            [Description("msExchEdgeSyncMservBackupLeaseLocation")]
            ATT_MS_EXCH_EDGE_SYNC_MSERV_BACKUP_LEASE_LOCATION = 1030522869,

            [Description("msExchEdgeSyncMservLocalCertificate")]
            ATT_MS_EXCH_EDGE_SYNC_MSERV_LOCAL_CERTIFICATE = 1030522867,

            [Description("msExchEdgeSyncMservPrimaryLeaseLocation")]
            ATT_MS_EXCH_EDGE_SYNC_MSERV_PRIMARY_LEASE_LOCATION = 1030522871,

            [Description("msExchEdgeSyncMservProvisionUrl")]
            ATT_MS_EXCH_EDGE_SYNC_MSERV_PROVISION_URL = 1030522865,

            [Description("msExchEdgeSyncMservRemoteCertificate")]
            ATT_MS_EXCH_EDGE_SYNC_MSERV_REMOTE_CERTIFICATE = 1030522868,

            [Description("msExchEdgeSyncMservSettingUrl")]
            ATT_MS_EXCH_EDGE_SYNC_MSERV_SETTING_URL = 1030522866,

            [Description("msExchEdgeSyncOptionDuration")]
            ATT_MS_EXCH_EDGE_SYNC_OPTION_DURATION = 1030522855,

            [Description("msExchEdgeSyncProviderAssemblyPath")]
            ATT_MS_EXCH_EDGE_SYNC_PROVIDER_ASSEMBLY_PATH = 1030522870,

            [Description("msExchEdgeSyncRecipientSyncInterval")]
            ATT_MS_EXCH_EDGE_SYNC_RECIPIENT_SYNC_INTERVAL = 1030522852,

            [Description("msExchEdgeSyncSynchronizationProvider")]
            ATT_MS_EXCH_EDGE_SYNC_SYNCHRONIZATION_PROVIDER = 1030522864,

            [Description("msExchFedAccountNamespace")]
            ATT_MS_EXCH_FED_ACCOUNT_NAMESPACE = 1030522883,

            [Description("msExchFedApplicationId")]
            ATT_MS_EXCH_FED_APPLICATION_ID = 1030522894,

            [Description("msExchFedApplicationURI")]
            ATT_MS_EXCH_FED_APPLICATION_URI = 1030522910,

            [Description("msExchFedClientTrust")]
            ATT_MS_EXCH_FED_CLIENT_TRUST = 1030522891,

            [Description("msExchFedDelegationTrust")]
            ATT_MS_EXCH_FED_DELEGATION_TRUST = 1030522890,

            [Description("msExchFedDomainNames")]
            ATT_MS_EXCH_FED_DOMAIN_NAMES = 1030522906,

            [Description("msExchFedEnabledActions")]
            ATT_MS_EXCH_FED_ENABLED_ACTIONS = 1030522909,

            [Description("msExchFedIsEnabled")]
            ATT_MS_EXCH_FED_IS_ENABLED = 1030522911,

            [Description("msExchFedMetadataEPR")]
            ATT_MS_EXCH_FED_METADATA_EPR = 1030522880,

            [Description("msExchFedMetadataPollInterval")]
            ATT_MS_EXCH_FED_METADATA_POLL_INTERVAL = 1030522913,

            [Description("msExchFedMetadataPutEPR")]
            ATT_MS_EXCH_FED_METADATA_PUT_EPR = 1030522882,

            [Description("msExchFedOrgAdminContact")]
            ATT_MS_EXCH_FED_ORG_ADMIN_CONTACT = 1030522892,

            [Description("msExchFedOrgApprovalContact")]
            ATT_MS_EXCH_FED_ORG_APPROVAL_CONTACT = 1030522893,

            [Description("msExchFedOrgCertificate")]
            ATT_MS_EXCH_FED_ORG_CERTIFICATE = 1030522887,

            [Description("msExchFedOrgPrevCertificate")]
            ATT_MS_EXCH_FED_ORG_PREV_CERTIFICATE = 1030522889,

            [Description("msExchFedOrgPrevPrivCertificate")]
            ATT_MS_EXCH_FED_ORG_PREV_PRIV_CERTIFICATE = 1030522888,

            [Description("msExchFedOrgPrivCertificate")]
            ATT_MS_EXCH_FED_ORG_PRIV_CERTIFICATE = 1030522886,

            [Description("msExchFedPolicyReferenceURI")]
            ATT_MS_EXCH_FED_POLICY_REFERENCE_URI = 1030522903,

            [Description("msExchFedTargetApplicationURI")]
            ATT_MS_EXCH_FED_TARGET_APPLICATION_URI = 1030522907,

            [Description("msExchFedTargetAutodiscoverEPR")]
            ATT_MS_EXCH_FED_TARGET_AUTODISCOVER_EPR = 1030522881,

            [Description("msExchFedTargetSharingEPR")]
            ATT_MS_EXCH_FED_TARGET_SHARING_EPR = 1030522908,

            [Description("msExchFedTokenIssuerCertReference")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_CERT_REFERENCE = 1030522899,

            [Description("msExchFedTokenIssuerCertificate")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_CERTIFICATE = 1030522900,

            [Description("msExchFedTokenIssuerEPR")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_EPR = 1030522898,

            [Description("msExchFedTokenIssuerMetadataEPR")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_METADATA_EPR = 1030522912,

            [Description("msExchFedTokenIssuerPrevCertReference")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_PREV_CERT_REFERENCE = 1030522901,

            [Description("msExchFedTokenIssuerPrevCertificate")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_PREV_CERTIFICATE = 1030522902,

            [Description("msExchFedTokenIssuerType")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_TYPE = 1030522896,

            [Description("msExchFedTokenIssuerURI")]
            ATT_MS_EXCH_FED_TOKEN_ISSUER_URI = 1030522897,

            [Description("msExchFedWebRequestorRedirectEPR")]
            ATT_MS_EXCH_FED_WEB_REQUESTOR_REDIRECT_EPR = 1030522904,

            [Description("msExchMailTipsLargeAudienceThreshold")]
            ATT_MS_EXCH_MAIL_TIPS_LARGE_AUDIENCE_THRESHOLD = 1030522872,

            [Description("msExchFedAcceptedDomainLink")]
            ATT_MS_EXCH_FED_ACCEPTED_DOMAIN_LINK = 1030522884,

            [Description("msExchFedAcceptedDomainBL")]
            ATT_MS_EXCH_FED_ACCEPTED_DOMAIN_BL = 1030522885,

            [Description("msExchJournalingReconciliationMailboxes")]
            ATT_MS_EXCH_JOURNALING_RECONCILIATION_MAILBOXES = 1030522919,

            [Description("msExchJournalingReconciliationPassword")]
            ATT_MS_EXCH_JOURNALING_RECONCILIATION_PASSWORD = 1030522918,

            [Description("msExchJournalingReconciliationUrl")]
            ATT_MS_EXCH_JOURNALING_RECONCILIATION_URL = 1030522916,

            [Description("msExchJournalingReconciliationUsername")]
            ATT_MS_EXCH_JOURNALING_RECONCILIATION_USERNAME = 1030522917,

            [Description("msExchReseller")]
            ATT_MS_EXCH_RESELLER = 1030522915,

            [Description("msExchRetentionComment")]
            ATT_MS_EXCH_RETENTION_COMMENT = 1030522920,

            [Description("msExchRetentionURL")]
            ATT_MS_EXCH_RETENTION_URL = 1030522922,

            [Description("msExchServicePlan")]
            ATT_MS_EXCH_SERVICE_PLAN = 1030522914,

            [Description("msExchAddressListPagingEnabled")]
            ATT_MS_EXCH_ADDRESS_LIST_PAGING_ENABLED = 1030522930,

            [Description("msExchSetupTime")]
            ATT_MS_EXCH_SETUP_TIME = 1030522929,

            [Description("msExchServerAssociationLink")]
            ATT_MS_EXCH_SERVER_ASSOCIATION_LINK = 1030522927,

            [Description("msExchServerAssociationBL")]
            ATT_MS_EXCH_SERVER_ASSOCIATION_BL = 1030522928,

            [Description("msExchOWAIMProviderType")]
            ATT_MS_EXCH_OWA_IM_PROVIDER_TYPE = 1030522932,

            [Description("msExchUMIPGatewayFlags2")]
            ATT_MS_EXCH_UM_IP_GATEWAY_FLAGS2 = 1030522931,

            [Description("msExchESEParamBackgroundDatabaseMaintenance")]
            ATT_MS_EXCH_ESE_PARAM_BACKGROUND_DATABASE_MAINTENANCE = 1030522935,

            [Description("msExchUMTcpListeningPort")]
            ATT_MS_EXCH_UM_TCP_LISTENING_PORT = 1030522933,

            [Description("msExchUMTlsListeningPort")]
            ATT_MS_EXCH_UM_TLS_LISTENING_PORT = 1030522934,

            [Description("msExchMDBAvailabilityGroupNetworkSettings")]
            ATT_MS_EXCH_MDB_AVAILABILITY_GROUP_NETWORK_SETTINGS = 1030522939,

            [Description("msExchOABLastNumberOfRecords")]
            ATT_MS_EXCH_OAB_LAST_NUMBER_OF_RECORDS = 1030522937,

            [Description("msExchOABLastTouchedTime")]
            ATT_MS_EXCH_OAB_LAST_TOUCHED_TIME = 1030522936,

            [Description("msExchOABPreferredSite")]
            ATT_MS_EXCH_OAB_PREFERRED_SITE = 1030522938,

            [Description("msExchUserBL")]
            ATT_MS_EXCH_USER_BL = 1030522940,

            [Description("msExchActivationConfig")]
            ATT_MS_EXCH_ACTIVATION_CONFIG = 1030522951,

            [Description("msExchAlternateMailboxes")]
            ATT_MS_EXCH_ALTERNATE_MAILBOXES = 1030522950,

            [Description("msExchContentAggregationFlags")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_FLAGS = 1030523000,

            [Description("msExchContentAggregationMaxAcceptedJobsPerProcessor")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_MAX_ACCEPTED_JOBS_PER_PROCESSOR = 1030522976,

            [Description("msExchContentAggregationMaxActiveJobsPerProcessor")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_MAX_ACTIVE_JOBS_PER_PROCESSOR = 1030522977,

            [Description("msExchContentAggregationMaxDispatchers")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_MAX_DISPATCHERS = 1030522996,

            [Description("msExchContentAggregationMaxDownloadItemsPerConnection")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_MAX_DOWNLOAD_ITEMS_PER_CONNECTION = 1030522993,

            [Description("msExchContentAggregationMaxDownloadSizePerConnection")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_MAX_DOWNLOAD_SIZE_PER_CONNECTION = 1030522992,

            [Description("msExchContentAggregationMaxDownloadSizePerItem")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_MAX_DOWNLOAD_SIZE_PER_ITEM = 1030522991,

            [Description("msExchContentAggregationMaxNumberOfAttempts")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_MAX_NUMBER_OF_ATTEMPTS = 1030522975,

            [Description("msExchContentAggregationProxyServerURL")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_PROXY_SERVER_URL = 1030522978,

            [Description("msExchContentAggregationRemoteConnectionTimeout")]
            ATT_MS_EXCH_CONTENT_AGGREGATION_REMOTE_CONNECTION_TIMEOUT = 1030522990,

            [Description("msExchDeltaSyncClientCertificateThumbprint")]
            ATT_MS_EXCH_DELTA_SYNC_CLIENT_CERTIFICATE_THUMBPRINT = 1030522994,

            [Description("msExchHttpProtocolLogAgeQuotaInHours")]
            ATT_MS_EXCH_HTTP_PROTOCOL_LOG_AGE_QUOTA_IN_HOURS = 1030522981,

            [Description("msExchHTTPProtocolLogDirectorySizeQuota")]
            ATT_MS_EXCH_HTTP_PROTOCOL_LOG_DIRECTORY_SIZE_QUOTA = 1030522982,

            [Description("msExchHTTPProtocolLogFilePath")]
            ATT_MS_EXCH_HTTP_PROTOCOL_LOG_FILE_PATH = 1030522980,

            [Description("msExchHTTPProtocolLogLoggingLevel")]
            ATT_MS_EXCH_HTTP_PROTOCOL_LOG_LOGGING_LEVEL = 1030522984,

            [Description("msExchHTTPProtocolLogPerFileSizeQuota")]
            ATT_MS_EXCH_HTTP_PROTOCOL_LOG_PER_FILE_SIZE_QUOTA = 1030522983,

            [Description("msExchFedAdminKey")]
            ATT_MS_EXCH_SHARING_ADMIN_KEY = 1030522943,

            [Description("msExchFedOrgNextCertificate")]
            ATT_MS_EXCH_SHARING_ORG_NEXT_CERTIFICATE = 1030522947,

            [Description("msExchFedOrgNextPrivCertificate")]
            ATT_MS_EXCH_SHARING_ORG_NEXT_PRIV_CERTIFICATE = 1030522948,

            [Description("msExchSharingPolicyDomains")]
            ATT_MS_EXCH_SHARING_POLICY_DOMAINS = 1030522944,

            [Description("msExchSharingPolicyIsEnabled")]
            ATT_MS_EXCH_SHARING_POLICY_IS_ENABLED = 1030523001,

            [Description("msExchSharingPolicyLink")]
            ATT_MS_EXCH_SHARING_POLICY_LINK = 1030522946,

            [Description("msExchFedProvisioningProvider")]
            ATT_MS_EXCH_SHARING_PROVISIONING_PROVIDER = 1030522942,

            [Description("msExchSMTPReceiveMessageRateSource")]
            ATT_MS_EXCH_SMTP_RECEIVE_MESSAGE_RATE_SOURCE = 1030522954,

            [Description("msExchSyncLogAgeQuotaInHours")]
            ATT_MS_EXCH_SYNC_LOG_AGE_QUOTA_IN_HOURS = 1030522987,

            [Description("msExchSyncLogDirectorySizeQuota")]
            ATT_MS_EXCH_SYNC_LOG_DIRECTORY_SIZE_QUOTA = 1030522988,

            [Description("msExchSyncLogFilePath")]
            ATT_MS_EXCH_SYNC_LOG_FILE_PATH = 1030522986,

            [Description("msExchSyncLogPerFileSizeQuota")]
            ATT_MS_EXCH_SYNC_LOG_PER_FILE_SIZE_QUOTA = 1030522989,

            [Description("msExchSystemMessageCustomizations")]
            ATT_MS_EXCH_SYSTEM_MESSAGE_CUSTOMIZATIONS = 1030522949,

            [Description("msExchUMMissedCallText")]
            ATT_MS_EXCH_UM_MISSED_CALL_TEXT = 1030522941,

            [Description("msExchAdminAuditLogAgeLimit")]
            ATT_MS_EXCH_ADMIN_AUDIT_LOG_AGE_LIMIT = 1030523050,

            [Description("msExchAdminAuditLogCmdlets")]
            ATT_MS_EXCH_ADMIN_AUDIT_LOG_CMDLETS = 1030523051,

            [Description("msExchAdminAuditLogFlags")]
            ATT_MS_EXCH_ADMIN_AUDIT_LOG_FLAGS = 1030523049,

            [Description("msExchAdminAuditLogMailbox")]
            ATT_MS_EXCH_ADMIN_AUDIT_LOG_MAILBOX = 1030523053,

            [Description("msExchAdminAuditLogParameters")]
            ATT_MS_EXCH_ADMIN_AUDIT_LOG_PARAMETERS = 1030523052,

            [Description("msExchAlternateFileShareWitness")]
            ATT_MS_EXCH_ALTERNATE_FILE_SHARE_WITNESS = 1030522959,

            [Description("msExchAlternateFileShareWitnessDirectory")]
            ATT_MS_EXCH_ALTERNATE_FILE_SHARE_WITNESS_DIRECTORY = 1030522960,

            [Description("msExchContinuousReplicationMaxMemoryPerMDB")]
            ATT_MS_EXCH_CONTINUOUS_REPLICATION_MAX_MEMORY_PER_MDB = 1030522961,

            [Description("msExchDatacenterActivationMode")]
            ATT_MS_EXCH_DATACENTER_ACTIVATION_MODE = 1030522956,

            [Description("msExchFedLocalRecipientAddress")]
            ATT_MS_EXCH_FED_LOCAL_RECIPIENT_ADDRESS = 1030522997,

            [Description("msExchFedRemoteTargetAddress")]
            ATT_MS_EXCH_FED_REMOTE_TARGET_ADDRESS = 1030522998,

            [Description("msExchMDBAvailabilityGroupIPv4Addresses")]
            ATT_MS_EXCH_MDB_AVAILABILITY_GROUP_IPV4_ADDRESSES = 1030522955,

            [Description("msExchMobileOTAUpdateMode")]
            ATT_MS_EXCH_MOBILE_OTA_UPDATE_MODE = 1030523012,

            [Description("msExchOrganizationFlags")]
            ATT_MS_EXCH_ORGANIZATION_FLAGS = 1030523054,

            [Description("msExchRecoveryPointObjectiveInterADSite")]
            ATT_MS_EXCH_RECOVERY_POINT_OBJECTIVE_INTER_AD_SITE = 1030522963,

            [Description("msExchRecoveryPointObjectiveIntraADSite")]
            ATT_MS_EXCH_RECOVERY_POINT_OBJECTIVE_INTRA_AD_SITE = 1030522962,

            [Description("msExchRelationTags")]
            ATT_MS_EXCH_RELATION_TAGS = 1030523044,

            [Description("msExchSharingRelationshipForExternalOrganizationEmail")]
            ATT_MS_EXCH_SHARING_RELATIONSHIP_FOR_EXTERNAL_ORGANIZATION_EMAIL = 1030522999,

            [Description("msExchStartedMailboxServers")]
            ATT_MS_EXCH_STARTED_MAILBOX_SERVERS = 1030522958,

            [Description("msExchStoppedMailboxServers")]
            ATT_MS_EXCH_STOPPED_MAILBOX_SERVERS = 1030522957,

            [Description("msExchSupervisionListMaxLength")]
            ATT_MS_EXCH_SUPERVISION_LIST_MAX_LENGTH = 1030523048,

            [Description("msExchTransportMaxRecipientStatisticsLogAge")]
            ATT_MS_EXCH_TRANSPORT_MAX_RECIPIENT_STATISTICS_LOG_AGE = 1030523006,

            [Description("msExchTransportMaxServerStatisticsLogAge")]
            ATT_MS_EXCH_TRANSPORT_MAX_SERVER_STATISTICS_LOG_AGE = 1030523002,

            [Description("msExchTransportRecipientStatisticsDirectorySize")]
            ATT_MS_EXCH_TRANSPORT_RECIPIENT_STATISTICS_DIRECTORY_SIZE = 1030523008,

            [Description("msExchTransportRecipientStatisticsFileSize")]
            ATT_MS_EXCH_TRANSPORT_RECIPIENT_STATISTICS_FILE_SIZE = 1030523009,

            [Description("msExchTransportRecipientStatisticsPath")]
            ATT_MS_EXCH_TRANSPORT_RECIPIENT_STATISTICS_PATH = 1030523007,

            [Description("msExchTransportServerStatisticsDirectorySize")]
            ATT_MS_EXCH_TRANSPORT_SERVER_STATISTICS_DIRECTORY_SIZE = 1030523004,

            [Description("msExchTransportServerStatisticsFileSize")]
            ATT_MS_EXCH_TRANSPORT_SERVER_STATISTICS_FILE_SIZE = 1030523005,

            [Description("msExchTransportServerStatisticsPath")]
            ATT_MS_EXCH_TRANSPORT_SERVER_STATISTICS_PATH = 1030523003,

            [Description("msExchTransportSettingsAVFlags")]
            ATT_MS_EXCH_TRANSPORT_SETTINGS_AV_FLAGS = 1030523043,

            [Description("msExchUMAddresses")]
            ATT_MS_EXCH_UM_ADDRESSES = 1030523024,

            [Description("msExchUMAutoAttendantPromptChangeKey")]
            ATT_MS_EXCH_UM_AUTO_ATTENDANT_PROMPT_CHANGE_KEY = 1030523011,

            [Description("msExchUMDialPlanDialedNumbers")]
            ATT_MS_EXCH_UM_DIAL_PLAN_DIALED_NUMBERS = 1030523028,

            [Description("msExchUMDialPlanPromptChangeKey")]
            ATT_MS_EXCH_UM_DIAL_PLAN_PROMPT_CHANGE_KEY = 1030523010,

            [Description("msExchUMMailboxOVALanguage")]
            ATT_MS_EXCH_UM_MAILBOX_OVA_LANGUAGE = 1030523023,

            [Description("msExchUMPhoneProvider")]
            ATT_MS_EXCH_UM_PHONE_PROVIDER = 1030523027,

            [Description("msExchUMSiteRedirectTarget")]
            ATT_MS_EXCH_UM_SITE_REDIRECT_TARGET = 1030523029,

            [Description("msExchSupervisionUserLink")]
            ATT_MS_EXCH_SUPERVISION_USER_LINK = 1030523045,

            [Description("msExchSupervisionDLLink")]
            ATT_MS_EXCH_SUPERVISION_DL_LINK = 1030523046,

            [Description("msExchSupervisionOneOffLink")]
            ATT_MS_EXCH_SUPERVISION_ONE_OFF_LINK = 1030523047,

            [Description("msExchAssistantsMaintenanceSchedule")]
            ATT_MS_EXCH_ASSISTANTS_MAINTENANCE_SCHEDULE = 1030523075,

            [Description("msExchCalendarRepairDisabled")]
            ATT_MS_EXCH_CALENDAR_REPAIR_DISABLED = 1030523016,

            [Description("msExchCalendarRepairFlags")]
            ATT_MS_EXCH_CALENDAR_REPAIR_FLAGS = 1030523020,

            [Description("msExchCalendarRepairIntervalEndWindow")]
            ATT_MS_EXCH_CALENDAR_REPAIR_INTERVAL_END_WINDOW = 1030523017,

            [Description("msExchCalendarRepairIntervalStartWindow")]
            ATT_MS_EXCH_CALENDAR_REPAIR_INTERVAL_START_WINDOW = 1030523018,

            [Description("msExchCalendarRepairLogFileAgeLimit")]
            ATT_MS_EXCH_CALENDAR_REPAIR_LOG_FILE_AGE_LIMIT = 1030523021,

            [Description("msExchCalendarRepairLogFileSizeLimit")]
            ATT_MS_EXCH_CALENDAR_REPAIR_LOG_FILE_SIZE_LIMIT = 1030523022,

            [Description("msExchCalendarRepairLogPath")]
            ATT_MS_EXCH_CALENDAR_REPAIR_LOG_PATH = 1030523014,

            [Description("msExchCalendarRepairMaxThreads")]
            ATT_MS_EXCH_CALENDAR_REPAIR_MAX_THREADS = 1030523019,

            [Description("msExchControlPointFlags")]
            ATT_MS_EXCH_CONTROL_POINT_FLAGS = 1030523068,

            [Description("msExchInternetWebProxy")]
            ATT_MS_EXCH_INTERNET_WEB_PROXY = 1030523076,

            [Description("msExchMailboxMoveFlags")]
            ATT_MS_EXCH_MAILBOX_MOVE_FLAGS = 1030523080,

            [Description("msExchMailboxMoveRemoteHostName")]
            ATT_MS_EXCH_MAILBOX_MOVE_REMOTE_HOST_NAME = 1030523082,

            [Description("msExchMailboxMoveStatus")]
            ATT_MS_EXCH_MAILBOX_MOVE_STATUS = 1030523081,

            [Description("msExchMailboxPlanType")]
            ATT_MS_EXCH_MAILBOX_PLAN_TYPE = 1030523085,

            [Description("msExchRMSLicensingLocationUrl")]
            ATT_MS_EXCH_RMS_LICENSING_LOCATION_URL = 1030522969,

            [Description("msExchRMSPublishingLocationUrl")]
            ATT_MS_EXCH_RMS_PUBLISHING_LOCATION_URL = 1030522966,

            [Description("msExchRMSServiceLocationUrl")]
            ATT_MS_EXCH_RMS_SERVICE_LOCATION_URL = 1030522964,

            [Description("msExchRoleEntriesExt")]
            ATT_MS_EXCH_ROLE_ENTRIES_EXT = 1030523071,

            [Description("msExchRoleType")]
            ATT_MS_EXCH_ROLE_TYPE = 1030523070,

            [Description("msExchSharingDefaultPolicyLink")]
            ATT_MS_EXCH_SHARING_DEFAULT_POLICY_LINK = 1030523072,

            [Description("msExchSyncAccountsFlags")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_FLAGS = 1030523042,

            [Description("msExchSyncAccountsMax")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_MAX = 1030523041,

            [Description("msExchSyncAccountsPoisonAccountThreshold")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_POISON_ACCOUNT_THRESHOLD = 1030523036,

            [Description("msExchSyncAccountsPoisonItemThreshold")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_POISON_ITEM_THRESHOLD = 1030523037,

            [Description("msExchSyncAccountsPolicyDN")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_POLICY_DN = 1030523074,

            [Description("msExchSyncAccountsPollingInterval")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_POLLING_INTERVAL = 1030523038,

            [Description("msExchSyncAccountsTimeBeforeDormant")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_TIME_BEFORE_DORMANT = 1030523040,

            [Description("msExchSyncAccountsTimeBeforeInactive")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_TIME_BEFORE_INACTIVE = 1030523039,

            [Description("msExchSyncLogLoggingLevel")]
            ATT_MS_EXCH_SYNC_LOG_LOGGING_LEVEL = 1030523035,

            [Description("msExchSyncMailboxLogAgeQuotaInHours")]
            ATT_MS_EXCH_SYNC_MAILBOX_LOG_AGE_QUOTA_IN_HOURS = 1030523031,

            [Description("msExchSyncMailboxLogDirectorySizeQuota")]
            ATT_MS_EXCH_SYNC_MAILBOX_LOG_DIRECTORY_SIZE_QUOTA = 1030523032,

            [Description("msExchSyncMailboxLogFilePath")]
            ATT_MS_EXCH_SYNC_MAILBOX_LOG_FILE_PATH = 1030523030,

            [Description("msExchSyncMailboxLogLoggingLevel")]
            ATT_MS_EXCH_SYNC_MAILBOX_LOG_LOGGING_LEVEL = 1030523034,

            [Description("msExchSyncMailboxLogPerFileSizeQuota")]
            ATT_MS_EXCH_SYNC_MAILBOX_LOG_PER_FILE_SIZE_QUOTA = 1030523033,

            [Description("msExchTextMessagingState")]
            ATT_MS_EXCH_TEXT_MESSAGING_STATE = 1030523063,

            [Description("msExchUMGlobalCallRoutingScheme")]
            ATT_MS_EXCH_UM_GLOBAL_CALL_ROUTING_SCHEME = 1030523069,

            [Description("msExchUMLoadBalancerFQDN")]
            ATT_MS_EXCH_UM_LOAD_BALANCER_FQDN = 1030523077,

            [Description("msExchMailboxMoveTargetMDBLink")]
            ATT_MS_EXCH_MAILBOX_MOVE_TARGET_MDB_LINK = 1030523078,

            [Description("msExchMailboxMoveTargetMDBBL")]
            ATT_MS_EXCH_MAILBOX_MOVE_TARGET_MDB_BL = 1030523079,

            [Description("msExchDirsyncID")]
            ATT_MS_EXCH_DIRSYNC_ID = 1030523094,

            [Description("msExchManagementSiteLink")]
            ATT_MS_EXCH_MANAGEMENT_SITE_LINK = 1030523090,

            [Description("msExchUMAudioCodec2")]
            ATT_MS_EXCH_UM_AUDIO_CODEC_2 = 1030523093,

            [Description("msExchUMBusinessLocation")]
            ATT_MS_EXCH_UM_BUSINESS_LOCATION = 1030523092,

            [Description("msExchUMBusinessName")]
            ATT_MS_EXCH_UM_BUSINESS_NAME = 1030523091,

            [Description("msExchUMDefaultMailbox")]
            ATT_MS_EXCH_UM_DEFAULT_MAILBOX = 1030523088,

            [Description("msExchUMDefaultOutboundCallingLineID")]
            ATT_MS_EXCH_UM_DEFAULT_OUTBOUND_CALLING_LINE_ID = 1030523089,

            [Description("msExchUMWeekStartDay")]
            ATT_MS_EXCH_UM_WEEK_START_DAY = 1030523095,

            [Description("msExchDirsyncIdSourceAttribute")]
            ATT_MS_EXCH_DIRSYNC_ID_SOURCE_ATTRIBUTE = 1030523103,

            [Description("msExchGalsyncDisableLiveIdOnRemove")]
            ATT_MS_EXCH_GALSYNC_DISABLE_LIVE_ID_ON_REMOVE = 1030523098,

            [Description("msExchGalsyncFederatedTenantSourceAttribute")]
            ATT_MS_EXCH_GALSYNC_FEDERATED_TENANT_SOURCE_ATTRIBUTE = 1030523099,

            [Description("msExchGalsyncLastSyncRun")]
            ATT_MS_EXCH_GALSYNC_LAST_SYNC_RUN = 1030523108,

            [Description("msExchGalsyncPasswordFilePath")]
            ATT_MS_EXCH_GALSYNC_PASSWORD_FILE_PATH = 1030523101,

            [Description("msExchGalsyncProvisioningDomain")]
            ATT_MS_EXCH_GALSYNC_PROVISIONING_DOMAIN = 1030523105,

            [Description("msExchGalsyncResetPasswordOnNextLogon")]
            ATT_MS_EXCH_GALSYNC_RESET_PASSWORD_ON_NEXT_LOGON = 1030523102,

            [Description("msExchGalsyncSchedule")]
            ATT_MS_EXCH_GALSYNC_SCHEDULE = 1030523111,

            [Description("msExchGalsyncSourceActiveDirectorySchemaVersion")]
            ATT_MS_EXCH_GALSYNC_SOURCE_ACTIVE_DIRECTORY_SCHEMA_VERSION = 1030523104,

            [Description("msExchGalsyncWlidUseSmtpPrimary")]
            ATT_MS_EXCH_GALSYNC_WLID_USE_SMTP_PRIMARY = 1030523100,

            [Description("msExchMDBCopyParentClass")]
            ATT_MS_EXCH_MDB_COPY_PARENT_CLASS = 1030523106,

            [Description("msExchRBACPolicyFlags")]
            ATT_MS_EXCH_RBAC_POLICY_FLAGS = 1030523110,

            [Description("msExchUMForwardingAddressTemplate")]
            ATT_MS_EXCH_UM_FORWARDING_ADDRESS_TEMPLATE = 1030523107,

            [Description("msExchRBACPolicyLink")]
            ATT_MS_EXCH_RBAC_POLICY_LINK = 1030523109,

            [Description("msExchArchiveGUID")]
            ATT_MS_EXCH_ARCHIVE_GUID = 1030523123,

            [Description("msExchArchiveName")]
            ATT_MS_EXCH_ARCHIVE_NAME = 1030523121,

            [Description("msExchArchiveQuota")]
            ATT_MS_EXCH_ARCHIVE_QUOTA = 1030523122,

            [Description("msExchArchiveWarnQuota")]
            ATT_MS_EXCH_ARCHIVE_WARN_QUOTA = 1030523173,

            [Description("msExchConfigFilter")]
            ATT_MS_EXCH_CONFIG_FILTER = 1030523112,

            [Description("msExchOrgFederatedMailbox")]
            ATT_MS_EXCH_ORG_FEDERATED_MAILBOX = 1030523125,

            [Description("msExchPreviousHomeMDB")]
            ATT_MS_EXCH_PREVIOUS_HOME_MDB = 1030523130,

            [Description("msExchSmtpMaxMessagesPerConnection")]
            ATT_MS_EXCH_SMTP_MAX_MESSAGES_PER_CONNECTION = 1030523117,

            [Description("msExchUMFaxServerURI")]
            ATT_MS_EXCH_UM_FAX_SERVER_URI = 1030523113,

            [Description("msExchAvailabilityPerUserAccountBL")]
            ATT_MS_EXCH_AVAILABILITY_PER_USER_ACCOUNT_BL = 1030523142,

            [Description("msExchAvailabilityOrgWideAccountBL")]
            ATT_MS_EXCH_AVAILABILITY_ORG_WIDE_ACCOUNT_BL = 1030523141,

            [Description("msExchOWATranscodingFileTypesBL")]
            ATT_MS_EXCH_OWA_TRANSCODING_FILE_TYPES_BL = 1030523127,

            [Description("msExchOWAAllowedFileTypesBL")]
            ATT_MS_EXCH_OWA_ALLOWED_FILE_TYPES_BL = 1030523148,

            [Description("msExchOWAAllowedMimeTypesBL")]
            ATT_MS_EXCH_OWA_ALLOWED_MIME_TYPES_BL = 1030523153,

            [Description("msExchOWAForceSaveFileTypesBL")]
            ATT_MS_EXCH_OWA_FORCE_SAVE_FILE_TYPES_BL = 1030523159,

            [Description("msExchOWAForceSaveMIMETypesBL")]
            ATT_MS_EXCH_OWA_FORCE_SAVE_MIME_TYPES_BL = 1030523143,

            [Description("msExchOWABlockedFileTypesBL")]
            ATT_MS_EXCH_OWA_BLOCKED_FILE_TYPES_BL = 1030523150,

            [Description("msExchOWABlockedMIMETypesBL")]
            ATT_MS_EXCH_OWA_BLOCKED_MIME_TYPES_BL = 1030523154,

            [Description("msExchOWARemoteDocumentsAllowedServersBL")]
            ATT_MS_EXCH_OWA_REMOTE_DOCUMENTS_ALLOWED_SERVERS_BL = 1030523161,

            [Description("msExchOWARemoteDocumentsBlockedServersBL")]
            ATT_MS_EXCH_OWA_REMOTE_DOCUMENTS_BLOCKED_SERVERS_BL = 1030523144,

            [Description("msExchOWARemoteDocumentsInternalDomainSuffixListBL")]
            ATT_MS_EXCH_OWA_REMOTE_DOCUMENTS_INTERNAL_DOMAIN_SUFFIX_LIST_BL = 1030523151,

            [Description("msExchOWATranscodingMimeTypesBL")]
            ATT_MS_EXCH_OWA_TRANSCODING_MIME_TYPES_BL = 1030523157,

            [Description("msExchSMTPReceiveDefaultAcceptedDomainBL")]
            ATT_MS_EXCH_SMTP_RECEIVE_DEFAULT_ACCEPTED_DOMAIN_BL = 1030523162,

            [Description("msExchMobileRemoteDocumentsAllowedServersBL")]
            ATT_MS_EXCH_MOBILE_REMOTE_DOCUMENTS_ALLOWED_SERVERS_BL = 1030523163,

            [Description("msExchMobileRemoteDocumentsBlockedServersBL")]
            ATT_MS_EXCH_MOBILE_REMOTE_DOCUMENTS_BLOCKED_SERVERS_BL = 1030523146,

            [Description("msExchMobileRemoteDocumentsInternalDomainSuffixListBL")]
            ATT_MS_EXCH_MOBILE_REMOTE_DOCUMENTS_INTERNAL_DOMAIN_SUFFIX_LIST_BL = 1030523155,

            [Description("msExchServerSiteBL")]
            ATT_MS_EXCH_SERVER_SITE_BL = 1030523149,

            [Description("msExchOrganizationsGlobalAddressListsBL")]
            ATT_MS_EXCH_ORGANIZATIONS_GLOBAL_ADDRESS_LISTS_BL = 1030523158,

            [Description("msExchOrganizationsAddressBookRootsBL")]
            ATT_MS_EXCH_ORGANIZATIONS_ADDRESS_BOOK_ROOTS_BL = 1030523152,

            [Description("msExchOrganizationsTemplateRootsBL")]
            ATT_MS_EXCH_ORGANIZATIONS_TEMPLATE_ROOTS_BL = 1030523147,

            [Description("msExchParentPlanBL")]
            ATT_MS_EXCH_PARENT_PLAN_BL = 1030523126,

            [Description("msExchSupervisionUserBL")]
            ATT_MS_EXCH_SUPERVISION_USER_BL = 1030523145,

            [Description("msExchSupervisionDLBL")]
            ATT_MS_EXCH_SUPERVISION_DL_BL = 1030523160,

            [Description("msExchSupervisionOneOffBL")]
            ATT_MS_EXCH_SUPERVISION_ONE_OFF_BL = 1030523156,

            [Description("msExchRBACPolicyBL")]
            ATT_MS_EXCH_RBAC_POLICY_BL = 1030523128,

            [Description("msExchArchiveDatabaseLink")]
            ATT_MS_EXCH_ARCHIVE_DATABASE_LINK = 1030523124,

            [Description("msExchArchiveDatabaseBL")]
            ATT_MS_EXCH_ARCHIVE_DATABASE_BL = 1030523129,

            [Description("msExchAllowCrossSiteRPCClientAccess")]
            ATT_MS_EXCH_ALLOW_CROSS_SITE_RPC_CLIENT_ACCESS = 1030523205,

            [Description("msExchDataMoveReplicationConstraint")]
            ATT_MS_EXCH_DATA_MOVE_REPLICATION_CONSTRAINT = 1030523233,

            [Description("msExchDeviceAccessRuleCharacteristic")]
            ATT_MS_EXCH_DEVICE_ACCESS_RULE_CHARACTERISTIC = 1030523178,

            [Description("msExchDeviceAccessRuleQueryString")]
            ATT_MS_EXCH_DEVICE_ACCESS_RULE_QUERY_STRING = 1030523177,

            [Description("msExchDeviceAccessState")]
            ATT_MS_EXCH_DEVICE_ACCESS_STATE = 1030523179,

            [Description("msExchDeviceAccessStateReason")]
            ATT_MS_EXCH_DEVICE_ACCESS_STATE_REASON = 1030523180,

            [Description("msExchDeviceEASVersion")]
            ATT_MS_EXCH_DEVICE_EAS_VERSION = 1030523181,

            [Description("msExchDumpsterQuota")]
            ATT_MS_EXCH_DUMPSTER_QUOTA = 1030523188,

            [Description("msExchDumpsterWarningQuota")]
            ATT_MS_EXCH_DUMPSTER_WARNING_QUOTA = 1030523189,

            [Description("msExchEdgeSyncAdvancedConfiguration")]
            ATT_MS_EXCH_EDGE_SYNC_ADVANCED_CONFIGURATION = 1030523187,

            [Description("msExchEdgeSyncEHFBackupLeaseLocation")]
            ATT_MS_EXCH_EDGE_SYNC_EHF_BACKUP_LEASE_LOCATION = 1030523213,

            [Description("msExchEdgeSyncEHFPassword")]
            ATT_MS_EXCH_EDGE_SYNC_EHF_PASSWORD = 1030523224,

            [Description("msExchEdgeSyncEHFPrimaryLeaseLocation")]
            ATT_MS_EXCH_EDGE_SYNC_EHF_PRIMARY_LEASE_LOCATION = 1030523212,

            [Description("msExchEdgeSyncEHFProvisioningURL")]
            ATT_MS_EXCH_EDGE_SYNC_EHF_PROVISIONING_URL = 1030523211,

            [Description("msExchEdgeSyncEHFResellerID")]
            ATT_MS_EXCH_EDGE_SYNC_EHF_RESELLER_ID = 1030523225,

            [Description("msExchEdgeSyncEHFUserName")]
            ATT_MS_EXCH_EDGE_SYNC_EHF_USER_NAME = 1030523223,

            [Description("msExchEdgeSyncRetryCount")]
            ATT_MS_EXCH_EDGE_SYNC_RETRY_COUNT = 1030523186,

            [Description("msExchESEParamCachePriority")]
            ATT_MS_EXCH_ESE_PARAM_CACHE_PRIORITY = 1030523197,

            [Description("msExchESEParamReplayBackgroundDatabaseMaintenance")]
            ATT_MS_EXCH_ESE_PARAM_REPLAY_BACKGROUND_DATABASE_MAINTENANCE = 1030523196,

            [Description("msExchESEParamReplayCachePriority")]
            ATT_MS_EXCH_ESE_PARAM_REPLAY_CACHE_PRIORITY = 1030523198,

            [Description("msExchESEParamReplayCheckpointDepthMax")]
            ATT_MS_EXCH_ESE_PARAM_REPLAY_CHECKPOINT_DEPTH_MAX = 1030523195,

            [Description("msExchForeignGroupSID")]
            ATT_MS_EXCH_FOREIGN_GROUP_SID = 1030523241,

            [Description("msExchHostServerName")]
            ATT_MS_EXCH_HOST_SERVER_NAME = 1030523208,

            [Description("msExchMailboxMoveBatchName")]
            ATT_MS_EXCH_MAILBOX_MOVE_BATCH_NAME = 1030523118,

            [Description("msExchMaxActiveMailboxDatabases")]
            ATT_MS_EXCH_MAX_ACTIVE_MAILBOX_DATABASES = 1030523240,

            [Description("msExchMDBName")]
            ATT_MS_EXCH_MDB_NAME = 1030523209,

            [Description("msExchMobileAccessControl")]
            ATT_MS_EXCH_MOBILE_ACCESS_CONTROL = 1030523174,

            [Description("msExchMobileAdminRecipients")]
            ATT_MS_EXCH_MOBILE_ADMIN_RECIPIENTS = 1030523176,

            [Description("msExchMobileBlockedDeviceIDs")]
            ATT_MS_EXCH_MOBILE_BLOCKED_DEVICE_IDS = 1030523199,

            [Description("msExchMobileUserMailInsert")]
            ATT_MS_EXCH_MOBILE_USER_MAIL_INSERT = 1030523175,

            [Description("msExchObjectCountQuota")]
            ATT_MS_EXCH_OBJECT_COUNT_QUOTA = 1030523239,

            [Description("msExchPOPIMAPExternalConnectionSettings")]
            ATT_MS_EXCH_POP_IMAP_EXTERNAL_CONNECTION_SETTINGS = 1030523183,

            [Description("msExchPOPIMAPInternalConnectionSettings")]
            ATT_MS_EXCH_POP_IMAP_INTERNAL_CONNECTION_SETTINGS = 1030523185,

            [Description("msExchRCAThrottlingPolicyState")]
            ATT_MS_EXCH_RCA_THROTTLING_POLICY_STATE = 1030523242,

            [Description("msExchSyncAccountsSuccessivePoisonItemsThreshold")]
            ATT_MS_EXCH_SYNC_ACCOUNTS_SUCCESSIVE_POISON_ITEMS_THRESHOLD = 1030523140,

            [Description("msExchSyncHubHealthLogAgeQuotaInHours")]
            ATT_MS_EXCH_SYNC_HUB_HEALTH_LOG_AGE_QUOTA_IN_HOURS = 1030523132,

            [Description("msExchSyncHubHealthLogDirectorySizeQuota")]
            ATT_MS_EXCH_SYNC_HUB_HEALTH_LOG_DIRECTORY_SIZE_QUOTA = 1030523133,

            [Description("msExchSyncHubHealthLogFilePath")]
            ATT_MS_EXCH_SYNC_HUB_HEALTH_LOG_FILE_PATH = 1030523131,

            [Description("msExchSyncHubHealthLogPerFileSizeQuota")]
            ATT_MS_EXCH_SYNC_HUB_HEALTH_LOG_PER_FILE_SIZE_QUOTA = 1030523134,

            [Description("msExchSyncMailboxHealthLogAgeQuotaInHours")]
            ATT_MS_EXCH_SYNC_MAILBOX_HEALTH_LOG_AGE_QUOTA_IN_HOURS = 1030523136,

            [Description("msExchSyncMailboxHealthLogDirectorySizeQuota")]
            ATT_MS_EXCH_SYNC_MAILBOX_HEALTH_LOG_DIRECTORY_SIZE_QUOTA = 1030523137,

            [Description("msExchSyncMailboxHealthLogFilePath")]
            ATT_MS_EXCH_SYNC_MAILBOX_HEALTH_LOG_FILE_PATH = 1030523135,

            [Description("msExchSyncMailboxHealthLogPerFileSizeQuota")]
            ATT_MS_EXCH_SYNC_MAILBOX_HEALTH_LOG_PER_FILE_SIZE_QUOTA = 1030523138,

            [Description("msExchTenantPerimeterSettingsFlags")]
            ATT_MS_EXCH_TENANT_PERIMETER_SETTINGS_FLAGS = 1030523194,

            [Description("msExchTenantPerimeterSettingsGatewayIPAddresses")]
            ATT_MS_EXCH_TENANT_PERIMETER_SETTINGS_GATEWAY_IP_ADDRESSES = 1030523190,

            [Description("msExchTenantPerimeterSettingsInternalServerIPAddresses")]
            ATT_MS_EXCH_TENANT_PERIMETER_SETTINGS_INTERNAL_SERVER_IP_ADDRESSES = 1030523191,

            [Description("msExchTenantPerimeterSettingsOrgID")]
            ATT_MS_EXCH_TENANT_PERIMETER_SETTINGS_ORG_ID = 1030523222,

            [Description("msExchThirdPartySynchronousReplication")]
            ATT_MS_EXCH_THIRD_PARTY_SYNCHRONOUS_REPLICATION = 1030523232,

            [Description("msExchUMCertificateThumbprint")]
            ATT_MS_EXCH_UM_CERTIFICATE_THUMBPRINT = 1030523204,

            [Description("msExchUMStartupMode")]
            ATT_MS_EXCH_UM_STARTUP_MODE = 1030523200,

            [Description("msExchVoiceMailPreviewPartnerAddress")]
            ATT_MS_EXCH_VOICE_MAIL_PREVIEW_PARTNER_ADDRESS = 1030523114,

            [Description("msExchVoiceMailPreviewPartnerAssignedID")]
            ATT_MS_EXCH_VOICE_MAIL_PREVIEW_PARTNER_ASSIGNED_ID = 1030523221,

            [Description("msExchVoiceMailPreviewPartnerMaxDeliveryDelay")]
            ATT_MS_EXCH_VOICE_MAIL_PREVIEW_PARTNER_MAX_DELIVERY_DELAY = 1030523220,

            [Description("msExchVoiceMailPreviewPartnerMaxMessageDuration")]
            ATT_MS_EXCH_VOICE_MAIL_PREVIEW_PARTNER_MAX_MESSAGE_DURATION = 1030523219,

            [Description("msExchMailboxMoveSourceMDBLink")]
            ATT_MS_EXCH_MAILBOX_MOVE_SOURCE_MDB_LINK = 1030523119,

            [Description("msExchMailboxMoveSourceMDBBL")]
            ATT_MS_EXCH_MAILBOX_MOVE_SOURCE_MDB_BL = 1030523120,

            [Description("msExchRMSComputerAccountsLink")]
            ATT_MS_EXCH_RMS_COMPUTER_ACCOUNTS_LINK = 1030523172,

            [Description("msExchRMSComputerAccountsBL")]
            ATT_MS_EXCH_RMS_COMPUTER_ACCOUNTS_BL = 1030523203,

            [Description("msExchDelegateListLink")]
            ATT_MS_EXCH_DELEGATE_LIST_LINK = 1030523210,

            [Description("msExchDelegateListBL")]
            ATT_MS_EXCH_DELEGATE_LIST_BL = 1030523218,

            [Description("msExchDeviceAccessControlRuleLink")]
            ATT_MS_EXCH_DEVICE_ACCESS_CONTROL_RULE_LINK = 1030523182,

            [Description("msExchDeviceAccessControlRuleBL")]
            ATT_MS_EXCH_DEVICE_ACCESS_CONTROL_RULE_BL = 1030523184,

            [Description("msExchIntendedMailboxPlanLink")]
            ATT_MS_EXCH_INTENDED_MAILBOX_PLAN_LINK = 1030523243,

            [Description("msExchIntendedMailboxPlanBL")]
            ATT_MS_EXCH_INTENDED_MAILBOX_PLAN_BL = 1030523244,

            [Description("msExch2003Url")]
            ATT_MS_EXCH_2003_URL = 1030523246,

            [Description("msExchLegacyRedirectType")]
            ATT_MS_EXCH_LEGACY_REDIRECT_TYPE = 1030523247,

            [Description("msExchLicenseToken")]
            ATT_MS_EXCH_LICENSE_TOKEN = 1030523250,

            [Description("msExchMailboxFolderSet2")]
            ATT_MS_EXCH_MAILBOX_FOLDER_SET_2 = 1030523248,

            [Description("msExchObjectID")]
            ATT_MS_EXCH_OBJECT_ID = 1030523249,

            [Description("msExchContentConversionSettings")]
            ATT_MS_EXCH_CONTENT_CONVERSION_SETTINGS = 1030523170,

            [Description("msExchIMAP4Settings")]
            ATT_MS_EXCH_IMAP4_SETTINGS = 1030523165,

            [Description("msExchManagementSettings")]
            ATT_MS_EXCH_MANAGEMENT_SETTINGS = 1030523171,

            [Description("msExchMobileSettings")]
            ATT_MS_EXCH_MOBILE_SETTINGS = 1030523169,

            [Description("msExchOWASettings")]
            ATT_MS_EXCH_OWA_SETTINGS = 1030523168,

            [Description("msExchPOP3Settings")]
            ATT_MS_EXCH_POP3_SETTINGS = 1030523164,

            [Description("msExchTransportInboundSettings")]
            ATT_MS_EXCH_TRANSPORT_INBOUND_SETTINGS = 1030523166,

            [Description("msExchTransportOutboundSettings")]
            ATT_MS_EXCH_TRANSPORT_OUTBOUND_SETTINGS = 1030523167,

            [Description("msOrg-GroupSubtypeName")]
            ATT_MS_ORG_GROUP_SUBTYPE_NAME = 1072889859,

            [Description("msOrg-IsOrganizational")]
            ATT_MS_ORG_IS_ORGANIZATIONAL_GROUP = 1072889857,

            [Description("msOrg-OtherDisplayNames")]
            ATT_MS_ORG_OTHER_DISPLAY_NAMES = 1072889860,

            [Description("msOrg-Leaders")]
            ATT_MS_ORG_LEADERS = 1072889858,

            [Description("msOrg-LeadersBL")]
            ATT_MS_ORG_LEADERS_BL = 1072889861,

            [Description("msExchEwsApplicationAccessPolicy")]
            ATT_MS_EXCH_EWS_APPLICATION_ACCESS_POLICY = 1030523257,

            [Description("msExchEwsEnabled")]
            ATT_MS_EXCH_EWS_ENABLED = 1030523251,

            [Description("msExchEwsExceptions")]
            ATT_MS_EXCH_EWS_EXCEPTIONS = 1030523253,

            [Description("msExchEwsWellKnownApplicationPolicies")]
            ATT_MS_EXCH_EWS_WELL_KNOWN_APPLICATION_POLICIES = 1030523256,

            [Description("msExchArchiveAddress")]
            ATT_MS_EXCH_ARCHIVE_ADDRESS = 1030523264,

            [Description("msExchArchiveStatus")]
            ATT_MS_EXCH_ARCHIVE_STATUS = 1030523282,

            [Description("msExchAuthoritativePolicyTagGUID")]
            ATT_MS_EXCH_AUTHORITATIVE_POLICY_TAG_GUID = 1030523265,

            [Description("msExchAuthoritativePolicyTagNote")]
            ATT_MS_EXCH_AUTHORITATIVE_POLICY_TAG_NOTE = 1030523266,

            [Description("msExchAVAuthenticationService")]
            ATT_MS_EXCH_AV_AUTHENTICATION_SERVICE = 1030523267,

            [Description("msExchCapabilityIdentifiers")]
            ATT_MS_EXCH_CAPABILITY_IDENTIFIERS = 1030523261,

            [Description("msExchDistributionGroupDefaultOU")]
            ATT_MS_EXCH_DISTRIBUTION_GROUP_DEFAULT_OU = 1030523285,

            [Description("msExchDistributionGroupNameBlockedWordsList")]
            ATT_MS_EXCH_DISTRIBUTION_GROUP_NAME_BLOCKED_WORDS_LIST = 1030523284,

            [Description("msExchDistributionGroupNamingPolicy")]
            ATT_MS_EXCH_DISTRIBUTION_GROUP_NAMING_POLICY = 1030523283,

            [Description("msExchExternalDirectoryObjectId")]
            ATT_MS_EXCH_EXTERNAL_DIRECTORY_OBJECT_ID = 1030523290,

            [Description("msExchExternalDirectoryOrganizationId")]
            ATT_MS_EXCH_EXTERNAL_DIRECTORY_ORGANIZATION_ID = 1030523289,

            [Description("msExchLastExchangeChangedTime")]
            ATT_MS_EXCH_LAST_EXCHANGE_CHANGED_TIME = 1030523288,

            [Description("msExchMailboxMoveFilePath")]
            ATT_MS_EXCH_MAILBOX_MOVE_FILE_PATH = 1030523274,

            [Description("msExchMailboxMoveRequestGuid")]
            ATT_MS_EXCH_MAILBOX_MOVE_REQUEST_GUID = 1030523273,

            [Description("msExchMSOForwardSyncNonRecipientCookie")]
            ATT_MS_EXCH_MSO_FORWARD_SYNC_NON_RECIPIENT_COOKIE = 1030523287,

            [Description("msExchMSOForwardSyncRecipientCookie")]
            ATT_MS_EXCH_MSO_FORWARD_SYNC_RECIPIENT_COOKIE = 1030523286,

            [Description("msExchOWAIMCertificateThumbprint")]
            ATT_MS_EXCH_OWA_IM_CERTIFICATE_THUMBPRINT = 1030523258,

            [Description("msExchOWAIMServerName")]
            ATT_MS_EXCH_OWA_IM_SERVER_NAME = 1030523259,

            [Description("msExchPopImapLogFilePath")]
            ATT_MS_EXCH_POP_IMAP_LOG_FILE_PATH = 1030523268,

            [Description("msExchPopImapLogFileRolloverFrequency")]
            ATT_MS_EXCH_POP_IMAP_LOG_FILE_ROLLOVER_FREQUENCY = 1030523269,

            [Description("msExchPopImapPerLogFileSizeQuota")]
            ATT_MS_EXCH_POP_IMAP_PER_LOG_FILE_SIZE_QUOTA = 1030523270,

            [Description("msExchRemoteRecipientType")]
            ATT_MS_EXCH_REMOTE_RECIPIENT_TYPE = 1030523291,

            [Description("msExchSIPAccessService")]
            ATT_MS_EXCH_SIP_ACCESS_SERVICE = 1030523262,

            [Description("msExchUCVoiceMailSettings")]
            ATT_MS_EXCH_UC_VOICE_MAIL_SETTINGS = 1030523292,

            [Description("msExchUMDialPlanTimezone")]
            ATT_MS_EXCH_UM_DIAL_PLAN_TIMEZONE = 1030523293,

            [Description("msExchWhenMailboxCreated")]
            ATT_MS_EXCH_WHEN_MAILBOX_CREATED = 1030523260,

            [Description("msExchDefaultPublicMDB")]
            ATT_MS_EXCH_DEFAULT_PUBLIC_MDB = 1030523271,

            [Description("msExchDefaultPublicMDBBL")]
            ATT_MS_EXCH_DEFAULT_PUBLIC_MDB_BL = 1030523272,

            [Description("msExchMailboxMoveSourceUserLink")]
            ATT_MS_EXCH_MAILBOX_MOVE_SOURCE_USER_LINK = 1030523278,

            [Description("msExchMailboxMoveSourceUserBL")]
            ATT_MS_EXCH_MAILBOX_MOVE_SOURCE_USER_BL = 1030523279,

            [Description("msExchMailboxMoveStorageMDBLink")]
            ATT_MS_EXCH_MAILBOX_MOVE_STORAGE_MDB_LINK = 1030523280,

            [Description("msExchMailboxMoveStorageMDBBL")]
            ATT_MS_EXCH_MAILBOX_MOVE_STORAGE_MDB_BL = 1030523281,

            [Description("msExchMailboxMoveTargetUserLink")]
            ATT_MS_EXCH_MAILBOX_MOVE_TARGET_USER_LINK = 1030523276,

            [Description("msExchMailboxMoveTargetUserBL")]
            ATT_MS_EXCH_MAILBOX_MOVE_TARGET_USER_BL = 1030523277,

            [Description("msExchActivityBasedAuthenticationTimeoutInterval")]
            ATT_MS_EXCH_ACTIVITY_BASED_AUTHENTICATION_TIMEOUT_INTERVAL = 1030523299,

            [Description("msExchAnonymousThrottlingPolicyState")]
            ATT_MS_EXCH_ANONYMOUS_THROTTLING_POLICY_STATE = 1030523303,

            [Description("msExchEdgeSyncConnectorVersion")]
            ATT_MS_EXCH_EDGE_SYNC_CONNECTOR_VERSION = 1030523301,

            [Description("msExchGenericForwardingAddress")]
            ATT_MS_EXCH_GENERIC_FORWARDING_ADDRESS = 1030523300,

            [Description("msExchPartnerGroupID")]
            ATT_MS_EXCH_PARTNER_GROUP_ID = 1030523324,

            [Description("msExchSharedConfigServicePlanTag")]
            ATT_MS_EXCH_SHARED_CONFIG_SERVICE_PLAN_TAG = 1030523325,

            [Description("msExchSharedIdentityServerBoxRAC")]
            ATT_MS_EXCH_SHARED_IDENTITY_SERVER_BOX_RAC = 1030523319,

            [Description("msExchSharingAnonymousIdentities")]
            ATT_MS_EXCH_SHARING_ANONYMOUS_IDENTITIES = 1030523304,

            [Description("msExchTPDCSPName")]
            ATT_MS_EXCH_TPD_CSP_NAME = 1030523313,

            [Description("msExchTPDCSPType")]
            ATT_MS_EXCH_TPD_CSP_TYPE = 1030523312,

            [Description("msExchTPDDisplayName")]
            ATT_MS_EXCH_TPD_DISPLAY_NAME = 1030523305,

            [Description("msExchTPDExtranetCertificationUrl")]
            ATT_MS_EXCH_TPD_EXTRANET_CERTIFICATION_URL = 1030523322,

            [Description("msExchTPDExtranetLicensingUrl")]
            ATT_MS_EXCH_TPD_EXTRANET_LICENSING_URL = 1030523308,

            [Description("msExchTPDFlags")]
            ATT_MS_EXCH_TPD_FLAGS = 1030523306,

            [Description("msExchTPDIntranetCertificationUrl")]
            ATT_MS_EXCH_TPD_INTRANET_CERTIFICATION_URL = 1030523309,

            [Description("msExchTPDIntranetLicensingUrl")]
            ATT_MS_EXCH_TPD_INTRANET_LICENSING_URL = 1030523307,

            [Description("msExchTPDKeyContainerName")]
            ATT_MS_EXCH_TPD_KEY_CONTAINER_NAME = 1030523314,

            [Description("msExchTPDKeyID")]
            ATT_MS_EXCH_TPD_KEY_ID = 1030523310,

            [Description("msExchTPDKeyIDType")]
            ATT_MS_EXCH_TPD_KEY_IDTYPE = 1030523311,

            [Description("msExchTPDKeyNumber")]
            ATT_MS_EXCH_TPD_KEY_NUMBER = 1030523315,

            [Description("msExchTPDPrivateKey")]
            ATT_MS_EXCH_TPD_PRIVATE_KEY = 1030523316,

            [Description("msExchTPDSLCCertificateChain")]
            ATT_MS_EXCH_TPD_SLC_CERTIFICATE_CHAIN = 1030523317,

            [Description("msExchTPDTemplates")]
            ATT_MS_EXCH_TPD_TEMPLATES = 1030523318,

            [Description("msExchTransportResellerIntraTenantMailContentType")]
            ATT_MS_EXCH_TRANSPORT_RESELLER_INTRA_TENANT_MAIL_CONTENT_TYPE = 1030523297,

            [Description("msExchTransportResellerSettingsInboundGatewayID")]
            ATT_MS_EXCH_TRANSPORT_RESELLER_SETTINGS_INBOUND_GATEWAY_ID = 1030523295,

            [Description("msExchTransportResellerSettingsLink")]
            ATT_MS_EXCH_TRANSPORT_RESELLER_SETTINGS_LINK = 1030523302,

            [Description("msExchTransportResellerSettingsOutboundGatewayID")]
            ATT_MS_EXCH_TRANSPORT_RESELLER_SETTINGS_OUTBOUND_GATEWAY_ID = 1030523296,

            [Description("msExchUMSourceForestPolicyNames")]
            ATT_MS_EXCH_UM_SOURCE_FOREST_POLICY_NAMES = 1030523323,

            [Description("msExchSharedConfigLink")]
            ATT_MS_EXCH_SHARED_CONFIG_LINK = 1030523320,

            [Description("msExchSharedConfigBL")]
            ATT_MS_EXCH_SHARED_CONFIG_BL = 1030523321,

            [Description("msExchActiveInstanceSleepInterval")]
            ATT_MS_EXCH_ACTIVE_INSTANCE_SLEEP_INTERVAL = 1030523342,

            [Description("msExchAssistantsThrottleWorkcycle")]
            ATT_MS_EXCH_ASSISTANTS_THROTTLE_WORKCYCLE = 1030523337,

            [Description("msExchCommunityURL")]
            ATT_MS_EXCH_COMMUNITY_URL = 1030523345,

            [Description("msExchCommunityURLEnabled")]
            ATT_MS_EXCH_COMMUNITY_URL_ENABLED = 1030523346,

            [Description("msExchESEParamBackgroundDatabaseMaintenanceDelay")]
            ATT_MS_EXCH_ESE_PARAM_BACKGROUND_DATABASE_MAINTENANCE_DELAY = 1030523333,

            [Description("msExchESEParamBackgroundDatabaseMaintenanceIntervalMax")]
            ATT_MS_EXCH_ESE_PARAM_BACKGROUND_DATABASE_MAINTENANCE_INTERVAL_MAX = 1030523336,

            [Description("msExchESEParamBackgroundDatabaseMaintenanceIntervalMin")]
            ATT_MS_EXCH_ESE_PARAM_BACKGROUND_DATABASE_MAINTENANCE_INTERVAL_MIN = 1030523335,

            [Description("msExchESEParamBackgroundDatabaseMaintenanceSerialization")]
            ATT_MS_EXCH_ESE_PARAM_BACKGROUND_DATABASE_MAINTENANCE_SERIALIZATION = 1030523331,

            [Description("msExchESEParamHungIOAction")]
            ATT_MS_EXCH_ESE_PARAM_HUNG_IO_ACTION = 1030523344,

            [Description("msExchESEParamHungIOThreshold")]
            ATT_MS_EXCH_ESE_PARAM_HUNG_IO_THRESHOLD = 1030523343,

            [Description("msExchESEParamPreReadIOMax")]
            ATT_MS_EXCH_ESE_PARAM_PRE_READ_IO_MAX = 1030523329,

            [Description("msExchESEParamReplayBackgroundDatabaseMaintenanceDelay")]
            ATT_MS_EXCH_ESE_PARAM_REPLAY_BACKGROUND_DATABASE_MAINTENANCE_DELAY = 1030523334,

            [Description("msExchESEParamReplayPreReadIOMax")]
            ATT_MS_EXCH_ESE_PARAM_REPLAY_PRE_READ_IO_MAX = 1030523330,

            [Description("msExchIntendedServicePlan")]
            ATT_MS_EXCH_INTENDED_SERVICE_PLAN = 1030523338,

            [Description("msExchMRSRequestType")]
            ATT_MS_EXCH_MRS_REQUEST_TYPE = 1030523328,

            [Description("msExchNotificationAddress")]
            ATT_MS_EXCH_NOTIFICATION_ADDRESS = 1030523327,

            [Description("msExchNotificationEnabled")]
            ATT_MS_EXCH_NOTIFICATION_ENABLED = 1030523326,

            [Description("msExchPassiveInstanceSleepInterval")]
            ATT_MS_EXCH_PASSIVE_INSTANCE_SLEEP_INTERVAL = 1030523341,

            [Description("msExchSyncDaemonMaxVersion")]
            ATT_MS_EXCH_SYNC_DAEMON_MAX_VERSION = 1030523340,

            [Description("msExchSyncDaemonMinVersion")]
            ATT_MS_EXCH_SYNC_DAEMON_MIN_VERSION = 1030523339,

            [Description("msExchTransportIntraTenantMailContentType")]
            ATT_MS_EXCH_TRANSPORT_INTRA_TENANT_MAIL_CONTENT_TYPE = 1030523347,

            [Description("msExchTransportPartnerConnectorDomain")]
            ATT_MS_EXCH_TRANSPORT_PARTNER_CONNECTOR_DOMAIN = 1030523349,

            [Description("msExchTransportPartnerRoutingDomain")]
            ATT_MS_EXCH_TRANSPORT_PARTNER_ROUTING_DOMAIN = 1030523348,

            [Description("msExchAuditAdmin")]
            ATT_MS_EXCH_AUDIT_ADMIN = 1030523353,

            [Description("msExchAuditDelegate")]
            ATT_MS_EXCH_AUDIT_DELEGATE = 1030523354,

            [Description("msExchAuditDelegateAdmin")]
            ATT_MS_EXCH_AUDIT_DELEGATE_ADMIN = 1030523355,

            [Description("msExchAuditOwner")]
            ATT_MS_EXCH_AUDIT_OWNER = 1030523356,

            [Description("msExchBypassAudit")]
            ATT_MS_EXCH_BYPASS_AUDIT = 1030523358,

            [Description("msExchInterruptUserOnAuditFailure")]
            ATT_MS_EXCH_INTERRUPT_USER_ON_AUDIT_FAILURE = 1030523357,

            [Description("msExchIRMLogMaxAge")]
            ATT_MS_EXCH_IRM_LOG_MAX_AGE = 1030523360,

            [Description("msExchIRMLogMaxDirectorySize")]
            ATT_MS_EXCH_IRM_LOG_MAX_DIRECTORY_SIZE = 1030523361,

            [Description("msExchIRMLogMaxFileSize")]
            ATT_MS_EXCH_IRM_LOG_MAX_FILE_SIZE = 1030523362,

            [Description("msExchIRMLogPath")]
            ATT_MS_EXCH_IRM_LOG_PATH = 1030523363,

            [Description("msExchIsMSODirsyncEnabled")]
            ATT_MS_EXCH_IS_MSO_DIRSYNC_ENABLED = 1030523399,

            [Description("msExchIsMSODirsynced")]
            ATT_MS_EXCH_IS_MSO_DIRSYNCED = 1030523398,

            [Description("msExchMailboxAuditEnable")]
            ATT_MS_EXCH_MAILBOX_AUDIT_ENABLE = 1030523351,

            [Description("msExchMailboxAuditLogAgeLimit")]
            ATT_MS_EXCH_MAILBOX_AUDIT_LOG_AGE_LIMIT = 1030523352,

            [Description("msExchMobileOTANotificationMailInsert")]
            ATT_MS_EXCH_MOBILE_OTA_NOTIFICATION_MAIL_INSERT = 1030523400,

            [Description("msExchOnPremiseObjectGuid")]
            ATT_MS_EXCH_ON_PREMISE_OBJECT_GUID = 1030523397,

            [Description("msExchShadowAssistantName")]
            ATT_MS_EXCH_SHADOW_ASSISTANT_NAME = 1030523380,

            [Description("msExchShadowC")]
            ATT_MS_EXCH_SHADOW_C = 1030523368,

            [Description("msExchShadowCo")]
            ATT_MS_EXCH_SHADOW_CO = 1030523369,

            [Description("msExchShadowCountryCode")]
            ATT_MS_EXCH_SHADOW_COUNTRY_CODE = 1030523370,

            [Description("msExchShadowDepartment")]
            ATT_MS_EXCH_SHADOW_DEPARTMENT = 1030523371,

            [Description("msExchShadowDisplayName")]
            ATT_MS_EXCH_SHADOW_DISPLAY_NAME = 1030523372,

            [Description("msExchShadowFacsimileTelephoneNumber")]
            ATT_MS_EXCH_SHADOW_FACSIMILE_TELEPHONE_NUMBER = 1030523373,

            [Description("msExchShadowGivenName")]
            ATT_MS_EXCH_SHADOW_GIVEN_NAME = 1030523374,

            [Description("msExchShadowHomePhone")]
            ATT_MS_EXCH_SHADOW_HOME_PHONE = 1030523375,

            [Description("msExchShadowInfo")]
            ATT_MS_EXCH_SHADOW_INFO = 1030523376,

            [Description("msExchShadowL")]
            ATT_MS_EXCH_SHADOW_L = 1030523377,

            [Description("msExchShadowMailNickname")]
            ATT_MS_EXCH_SHADOW_MAIL_NICKNAME = 1030523378,

            [Description("msExchShadowMobile")]
            ATT_MS_EXCH_SHADOW_MOBILE = 1030523379,

            [Description("msExchShadowOtherFacsimileTelephone")]
            ATT_MS_EXCH_SHADOW_OTHER_FACSIMILE_TELEPHONE = 1030523381,

            [Description("msExchShadowOtherHomePhone")]
            ATT_MS_EXCH_SHADOW_OTHER_HOME_PHONE = 1030523382,

            [Description("msExchShadowOtherTelephone")]
            ATT_MS_EXCH_SHADOW_OTHER_TELEPHONE = 1030523383,

            [Description("msExchShadowPager")]
            ATT_MS_EXCH_SHADOW_PAGER = 1030523384,

            [Description("msExchShadowPhysicalDeliveryOfficeName")]
            ATT_MS_EXCH_SHADOW_PHYSICAL_DELIVERY_OFFICE_NAME = 1030523385,

            [Description("msExchShadowPostalCode")]
            ATT_MS_EXCH_SHADOW_POSTAL_CODE = 1030523386,

            [Description("msExchShadowProxyAddresses")]
            ATT_MS_EXCH_SHADOW_PROXY_ADDRESSES = 1030523387,

            [Description("msExchShadowSn")]
            ATT_MS_EXCH_SHADOW_SN = 1030523388,

            [Description("msExchShadowSt")]
            ATT_MS_EXCH_SHADOW_ST = 1030523389,

            [Description("msExchShadowStreetAddress")]
            ATT_MS_EXCH_SHADOW_STREET_ADDRESS = 1030523390,

            [Description("msExchShadowTelephoneAssistant")]
            ATT_MS_EXCH_SHADOW_TELEPHONE_ASSISTANT = 1030523391,

            [Description("msExchShadowTelephoneNumber")]
            ATT_MS_EXCH_SHADOW_TELEPHONE_NUMBER = 1030523392,

            [Description("msExchShadowTitle")]
            ATT_MS_EXCH_SHADOW_TITLE = 1030523393,

            [Description("msExchShadowWindowsLiveID")]
            ATT_MS_EXCH_SHADOW_WINDOWS_LIVE_ID = 1030523394,

            [Description("msExchShadowWWWHomePage")]
            ATT_MS_EXCH_SHADOW_WWW_HOME_PAGE = 1030523395,

            [Description("msExchSMTPExtendedProtectionPolicy")]
            ATT_MS_EXCH_SMTP_EXTENDED_PROTECTION_POLICY = 1030523350,

            [Description("msExchMailboxMoveSourceArchiveMDBLink")]
            ATT_MS_EXCH_MAILBOX_MOVE_SOURCE_ARCHIVE_MDB_LINK = 1030523364,

            [Description("msExchMailboxMoveSourceArchiveMDBBL")]
            ATT_MS_EXCH_MAILBOX_MOVE_SOURCE_ARCHIVE_MDB_BL = 1030523366,

            [Description("msExchMailboxMoveTargetArchiveMDBLink")]
            ATT_MS_EXCH_MAILBOX_MOVE_TARGET_ARCHIVE_MDB_LINK = 1030523365,

            [Description("msExchMailboxMoveTargetArchiveMDBBL")]
            ATT_MS_EXCH_MAILBOX_MOVE_TARGET_ARCHIVE_MDB_BL = 1030523367,

            [Description("msExchAddressBookFlags")]
            ATT_MS_EXCH_ADDRESS_BOOK_FLAGS = 1030523413,

            [Description("msExchDirsyncSourceObjectClass")]
            ATT_MS_EXCH_DIRSYNC_SOURCE_OBJECT_CLASS = 1030523426,

            [Description("msExchEdgeSyncEHFFlags")]
            ATT_MS_EXCH_EDGE_SYNC_EHF_FLAGS = 1030523425,

            [Description("msExchFedTargetOWAURL")]
            ATT_MS_EXCH_FED_TARGET_OWA_URL = 1030523403,

            [Description("msExchLitigationHoldDate")]
            ATT_MS_EXCH_LITIGATION_HOLD_DATE = 1030523414,

            [Description("msExchLitigationHoldOwner")]
            ATT_MS_EXCH_LITIGATION_HOLD_OWNER = 1030523415,

            [Description("msExchMailboxAuditLastAdminAccess")]
            ATT_MS_EXCH_MAILBOX_AUDIT_LAST_ADMIN_ACCESS = 1030523418,

            [Description("msExchMailboxAuditLastDelegateAccess")]
            ATT_MS_EXCH_MAILBOX_AUDIT_LAST_DELEGATE_ACCESS = 1030523419,

            [Description("msExchMailboxAuditLastExternalAccess")]
            ATT_MS_EXCH_MAILBOX_AUDIT_LAST_EXTERNAL_ACCESS = 1030523417,

            [Description("msExchMigrationLogAgeQuotaInHours")]
            ATT_MS_EXCH_MIGRATION_LOG_AGE_QUOTA_IN_HOURS = 1030523407,

            [Description("msExchMigrationLogDirectorySizeQuota")]
            ATT_MS_EXCH_MIGRATION_LOG_DIRECTORY_SIZE_QUOTA = 1030523408,

            [Description("msExchMigrationLogExtensionData")]
            ATT_MS_EXCH_MIGRATION_LOG_EXTENSION_DATA = 1030523412,

            [Description("msExchMigrationLogLogFilePath")]
            ATT_MS_EXCH_MIGRATION_LOG_LOG_FILE_PATH = 1030523409,

            [Description("msExchMigrationLogLoggingLevel")]
            ATT_MS_EXCH_MIGRATION_LOG_LOGGING_LEVEL = 1030523410,

            [Description("msExchMigrationLogPerFileSizeQuota")]
            ATT_MS_EXCH_MIGRATION_LOG_PER_FILE_SIZE_QUOTA = 1030523411,

            [Description("msExchMSOForwardSyncAsyncOperationIds")]
            ATT_MS_EXCH_MSO_FORWARD_SYNC_ASYNC_OPERATION_IDS = 1030523416,

            [Description("msExchPreviousMailboxGuid")]
            ATT_MS_EXCH_PREVIOUS_MAILBOX_GUID = 1030523420,

            [Description("msExchSIPSBCService")]
            ATT_MS_EXCH_SIP_SBC_SERVICE = 1030523402,

            [Description("msExchSmtpReceiveTlsDomainCapabilities")]
            ATT_MS_EXCH_SMTP_RECEIVE_TLS_DOMAIN_CAPABILITIES = 1030523406,

            [Description("msExchSmtpSendNdrLevel")]
            ATT_MS_EXCH_SMTP_SEND_NDR_LEVEL = 1030523405,

            [Description("msExchSmtpSendTlsDomain")]
            ATT_MS_EXCH_SMTP_SEND_TLS_DOMAIN = 1030523404,

            [Description("msExchTargetServerAdmins")]
            ATT_MS_EXCH_TARGET_SERVER_ADMINS = 1030523421,

            [Description("msExchTargetServerPartnerAdmins")]
            ATT_MS_EXCH_TARGET_SERVER_PARTNER_ADMINS = 1030523423,

            [Description("msExchTargetServerPartnerViewOnlyAdmins")]
            ATT_MS_EXCH_TARGET_SERVER_PARTNER_VIEW_ONLY_ADMINS = 1030523424,

            [Description("msExchTargetServerViewOnlyAdmins")]
            ATT_MS_EXCH_TARGET_SERVER_VIEW_ONLY_ADMINS = 1030523422,

            [Description("msExchMinorPartnerId")]
            ATT_MS_EXCH_MINOR_PARTNER_ID = 1030523429,

            [Description("msExchMobileOTANotificationMailInsert2")]
            ATT_MS_EXCH_MOBILE_OTA_NOTIFICATION_MAIL_INSERT_2 = 1030523428,

            [Description("msExchReconciliationCookies")]
            ATT_MS_EXCH_RECONCILIATION_COOKIES = 1030523431,

            [Description("msExchResponsibleForSites")]
            ATT_MS_EXCH_RESPONSIBLE_FOR_SITES = 1030523430,

            [Description("msExchShadowManagerLink")]
            ATT_MS_EXCH_SHADOW_MANAGER_LINK = 1030523427,

            [Description("msExchSupportedSharedConfigLink")]
            ATT_MS_EXCH_SUPPORTED_SHARED_CONFIG_LINK = 1030523435,

            [Description("msExchSupportedSharedConfigBL")]
            ATT_MS_EXCH_SUPPORTED_SHARED_CONFIG_BL = 1030523436,

            [Description("msExchCalculatedTargetAddress")]
            ATT_MS_EXCH_CALCULATED_TARGET_ADDRESS = 1030523434,

            [Description("msExchDeletionPeriod")]
            ATT_MS_EXCH_DELETION_PERIOD = 1030523438,

            [Description("msExchObjectsDeletedThisPeriod")]
            ATT_MS_EXCH_OBJECTS_DELETED_THIS_PERIOD = 1030523437,

            [Description("msExchShadowCompany")]
            ATT_MS_EXCH_SHADOW_COMPANY = 1030523441,

            [Description("msExchShadowInitials")]
            ATT_MS_EXCH_SHADOW_INITIALS = 1030523442,

            [Description("msExchDisabledArchiveGUID")]
            ATT_MS_EXCH_DISABLED_ARCHIVE_GUID = 1030523445,

            [Description("msExchMSOForwardSyncReplayList")]
            ATT_MS_EXCH_MSO_FORWARD_SYNC_REPLAY_LIST = 1030523444,

            [Description("msExchOWAFailbackURL")]
            ATT_MS_EXCH_OWA_FAILBACK_URL = 1030523439,

            [Description("msExchDisabledArchiveDatabaseLink")]
            ATT_MS_EXCH_DISABLED_ARCHIVE_DATABASE_LINK = 1030523446,

            [Description("msExchAdminAuditLogExcludedCmdlets")]
            ATT_MS_EXCH_ADMIN_AUDIT_LOG_EXCLUDED_CMDLETS = 1030523449,

            [Description("msExchCountries")]
            ATT_MS_EXCH_COUNTRIES = 1030523448,

            [Description("msExchUsageLocation")]
            ATT_MS_EXCH_USAGE_LOCATION = 1030523447,

            [Description("msExchExtendedProtectionSPNList")]
            ATT_MS_EXCH_EXTENDED_PROTECTION_SPNLIST = 1030523452,

            [Description("msExchMigrationLogDirectorySizeQuotaLarge")]
            ATT_MS_EXCH_MIGRATION_LOG_DIRECTORY_SIZE_QUOTA_LARGE = 1030523450,

            [Description("msExchPopImapExtendedProtectionPolicy")]
            ATT_MS_EXCH_POPIMAP_EXTENDED_PROTECTION_POLICY = 1030523451,

            [Description("msExchAddressBookPolicyLink")]
            ATT_MS_EXCH_ADDRESS_BOOK_POLICY_LINK = 1030523521,

            [Description("msExchAddressBookPolicyBL")]
            ATT_MS_EXCH_ADDRESS_BOOK_POLICY_BL = 1030523522,

            [Description("msExchAddressListsLink")]
            ATT_MS_EXCH_ADDRESS_LISTS_LINK = 1030523523,

            [Description("msExchAddressListsBL")]
            ATT_MS_EXCH_ADDRESS_LISTS_BL = 1030523524,

            [Description("msExchGlobalAddressListLink")]
            ATT_MS_EXCH_GLOBAL_ADDRESS_LIST_LINK = 1030523525,

            [Description("msExchGlobalAddressListBL")]
            ATT_MS_EXCH_GLOBAL_ADDRESS_LIST_BL = 1030523526,

            [Description("msExchOfflineAddressBookLink")]
            ATT_MS_EXCH_OFFLINE_ADDRESS_BOOK_LINK = 1030523527,

            [Description("msExchOfflineAddressBookBL")]
            ATT_MS_EXCH_OFFLINE_ADDRESS_BOOK_BL = 1030523528,

            [Description("msExchAllRoomListLink")]
            ATT_MS_EXCH_ALL_ROOM_LIST_LINK = 1030523529,

            [Description("msExchAllRoomListBL")]
            ATT_MS_EXCH_ALL_ROOM_LIST_BL = 1030523530,

            [Description("msExchCoexistenceDomains")]
            ATT_MS_EXCH_COEXISTENCE_DOMAINS = 1030523534,

            [Description("msExchCoexistenceExternalIPAddresses")]
            ATT_MS_EXCH_COEXISTENCE_EXTERNAL_IP_ADDRESSES = 1030523536,

            [Description("msExchCoexistenceFeatureFlags")]
            ATT_MS_EXCH_COEXISTENCE_FEATURE_FLAGS = 1030523535,

            [Description("msExchCoexistenceServers")]
            ATT_MS_EXCH_COEXISTENCE_SERVERS = 1030523533,

            [Description("msExchMRSProxyFlags")]
            ATT_MS_EXCH_MRS_PROXY_FLAGS = 1030523531,

            [Description("msExchMRSProxyMaxConnections")]
            ATT_MS_EXCH_MRS_PROXY_MAX_CONNECTIONS = 1030523532,

            [Description("msExchExtensionAttribute16")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_16 = 1030523564,

            [Description("msExchExtensionAttribute17")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_17 = 1030523565,

            [Description("msExchExtensionAttribute18")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_18 = 1030523566,

            [Description("msExchExtensionAttribute19")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_19 = 1030523567,

            [Description("msExchExtensionAttribute20")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_20 = 1030523568,

            [Description("msExchExtensionAttribute21")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_21 = 1030523569,

            [Description("msExchExtensionAttribute22")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_22 = 1030523570,

            [Description("msExchExtensionAttribute23")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_23 = 1030523571,

            [Description("msExchExtensionAttribute24")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_24 = 1030523572,

            [Description("msExchExtensionAttribute25")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_25 = 1030523573,

            [Description("msExchExtensionAttribute26")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_26 = 1030523574,

            [Description("msExchExtensionAttribute27")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_27 = 1030523575,

            [Description("msExchExtensionAttribute28")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_28 = 1030523576,

            [Description("msExchExtensionAttribute29")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_29 = 1030523577,

            [Description("msExchExtensionAttribute30")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_30 = 1030523578,

            [Description("msExchExtensionAttribute31")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_31 = 1030523579,

            [Description("msExchExtensionAttribute32")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_32 = 1030523580,

            [Description("msExchExtensionAttribute33")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_33 = 1030523581,

            [Description("msExchExtensionAttribute34")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_34 = 1030523582,

            [Description("msExchExtensionAttribute35")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_35 = 1030523583,

            [Description("msExchExtensionAttribute36")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_36 = 1030523584,

            [Description("msExchExtensionAttribute37")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_37 = 1030523585,

            [Description("msExchExtensionAttribute38")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_38 = 1030523586,

            [Description("msExchExtensionAttribute39")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_39 = 1030523587,

            [Description("msExchExtensionAttribute40")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_40 = 1030523588,

            [Description("msExchExtensionAttribute41")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_41 = 1030523589,

            [Description("msExchExtensionAttribute42")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_42 = 1030523590,

            [Description("msExchExtensionAttribute43")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_43 = 1030523591,

            [Description("msExchExtensionAttribute44")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_44 = 1030523592,

            [Description("msExchExtensionAttribute45")]
            ATT_MS_EXCH_EXTENSION_ATTRIBUTE_45 = 1030523593,

            [Description("msExchContentByteEncoderTypeFor7BitCharsets")]
            ATT_MS_EXCH_CONTENT_BYTE_ENCODER_TYPE_FOR_7_BIT_CHARSETS = 1030523634,

            [Description("msExchContentPreferredInternetCodePageForShiftJis")]
            ATT_MS_EXCH_CONTENT_PREFERRED_INTERNET_CODE_PAGE_FOR_SHIFT_JIS = 1030523635,

            [Description("msExchContentRequiredCharSetCoverage")]
            ATT_MS_EXCH_CONTENT_REQUIRED_CHAR_SET_COVERAGE = 1030523633,

            [Description("msExchCoexistenceOnPremisesSmartHost")]
            ATT_MS_EXCH_COEXISTENCE_ON_PREMISES_SMART_HOST = 1030523672,

            [Description("msExchCoexistenceSecureMailCertificateThumbprint")]
            ATT_MS_EXCH_COEXISTENCE_SECURE_MAIL_CERTIFICATE_THUMBPRINT = 1030523671,

            [Description("msExchCoexistenceTransportServers")]
            ATT_MS_EXCH_COEXISTENCE_TRANSPORT_SERVERS = 1030523670,

            [Description("msExchExtensionCustomAttribute1")]
            ATT_MS_EXCH_EXTENSION_CUSTOM_ATTRIBUTE_1 = 1030523556,

            [Description("msExchExtensionCustomAttribute2")]
            ATT_MS_EXCH_EXTENSION_CUSTOM_ATTRIBUTE_2 = 1030523557,

            [Description("msExchExtensionCustomAttribute3")]
            ATT_MS_EXCH_EXTENSION_CUSTOM_ATTRIBUTE_3 = 1030523558,

            [Description("msExchExtensionCustomAttribute4")]
            ATT_MS_EXCH_EXTENSION_CUSTOM_ATTRIBUTE_4 = 1030523559,

            [Description("msExchExtensionCustomAttribute5")]
            ATT_MS_EXCH_EXTENSION_CUSTOM_ATTRIBUTE_5 = 1030523560,

            [Description("msExchActiveSyncDeviceAutoBlockDuration")]
            ATT_MS_EXCH_ACTIVESYNC_DEVICE_AUTOBLOCK_DURATION = 1030523474,

            [Description("msExchActiveSyncDeviceAutoblockThresholdIncidenceDuration")]
            ATT_MS_EXCH_ACTIVESYNC_DEVICE_AUTOBLOCK_THRESHOLD_INCIDENCE_DURATION = 1030523475,

            [Description("msExchActiveSyncDeviceAutoblockThresholdIncidenceLimit")]
            ATT_MS_EXCH_ACTIVESYNC_DEVICE_AUTOBLOCK_THRESHOLD_INCIDENCE_LIMIT = 1030523472,

            [Description("msExchActiveSyncDeviceAutoblockThresholdType")]
            ATT_MS_EXCH_ACTIVESYNC_DEVICE_AUTOBLOCK_THRESHOLD_TYPE = 1030523471,

            [Description("msRTCSIP-TenantId")]
            ATT_MS_RTC_SIP_TENANTID = 2122776786,

            [Description("msRTCSIP-UserPolicies")]
            ATT_MS_RTC_SIP_USERPOLICIES = 2122776787,

            [Description("msRTCSIP-OwnerUrn")]
            ATT_MS_RTC_SIP_OWNERURN = 2122776788,

            [Description("msRTCSIP-TargetUserPolicies")]
            ATT_MS_RTC_SIP_TARGETUSERPOLICIES = 2122776789,

            [Description("msRTCSIP-DeploymentLocator")]
            ATT_MS_RTC_SIP_DEPLOYMENTLOCATOR = 2122776790,

            [Description("msRTCSIP-PrivateLine")]
            ATT_MS_RTC_SIP_PRIVATELINE = 2122776798,

            [Description("msRTCSIP-AcpInfo")]
            ATT_MS_RTC_SIP_ACPINFO = 2122776799,

            [Description("msRTCSIP-GroupingID")]
            ATT_MS_RTC_SIP_GROUPINGID = 2122776800

        }

    }

}
