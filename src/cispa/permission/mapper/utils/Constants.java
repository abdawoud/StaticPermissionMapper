package cispa.permission.mapper.utils;

import java.util.Arrays;
import java.util.List;

import cispa.permission.mapper.AnalysisConfig;

public class Constants {

	public static final String HOME = System.getProperty("user.home");
	public static final String OUTPUT = HOME + "/Desktop/resources/jimple_" + AnalysisConfig.TARGET_IMAGE;
	public static final String DEXES_FOLDER = HOME + "/Desktop/resources/" + AnalysisConfig.TARGET_IMAGE;
	public static final String ANDROID_JARS = HOME + "/Android/Sdk/platforms/";
	
	public static final String BINDER_INTERFACES_FILE = "binder_interfaces.txt";
	public static final String COMPONENT_PERMISSIONS_FILE = "component_permissions.txt";
	public static final String GLOBAL_MAPPING_FILE = "global_mapping.json";
	public static final String SERVICE_MAPPING_FILE = "service_mapping.json";
	public static final String MANAGER_MAPPING_FILE = "manager_mapping.json";
	public static final String PROXY_TO_FILE_MAPPING_FILE = "api_file_mapping.json";
	

	public static final String[][] PERMISSION_CHECKS = {
		// The following sinks are collected based on best effort and my experience in Android's access control!			
		{"android.content.Context", "int checkCallingOrSelfPermission(java.lang.String)"},
		{"android.content.Context", "int checkPermission(java.lang.String,int,int)"},
		{"android.content.Context", "void enforceCallingOrSelfPermission(java.lang.String,java.lang.String)"},
		{"android.content.Context", "int checkCallingPermission(java.lang.String)"},
		{"android.content.Context", "void enforceCallingPermission(java.lang.String,java.lang.String)"},
		{"android.content.Context", "void enforcePermission(java.lang.String,int,int,java.lang.String)"},
		{"android.content.pm.PackageManager", "int checkPermission(java.lang.String,java.lang.String)"},
		{"android.content.pm.IPackageManager", "int checkUidPermission(java.lang.String,int)"},
		{"android.content.pm.IPackageManager", "int checkPermission(java.lang.String,java.lang.String,int)"},
		{"com.android.server.pm.PackageManagerService", "int checkPermission(java.lang.String,java.lang.String,int)"},
		{"com.android.server.pm.PackageManagerService", "int checkUidPermission(java.lang.String,int)"},
		{"android.app.ActivityManagerInternal", "void enforceCallingPermission(java.lang.String,java.lang.String)"},
		{"com.android.server.am.ActivityManagerService", "int checkCallingPermission(java.lang.String)"},
		{"com.android.server.am.ActivityManagerService", "void enforceCallingPermission(java.lang.String,java.lang.String)"},
		{"com.android.server.am.ActivityManagerService", "int checkPermission(java.lang.String,int,int)"},
		{"com.android.server.am.ActivityManagerService", "void enforcePermission(java.lang.String,int,int,java.lang.String)"},
		{"android.app.ActivityManager", "int checkComponentPermission(java.lang.String,int,int,boolean)"},
		{"android.app.ActivityManager", "int checkUidPermission(java.lang.String,int)"},
		{"com.android.server.pm.permission.PermissionManagerService", "int checkUidPermission(java.lang.String,int)"},
		{"com.android.server.wm.ActivityTaskManagerInternal", "void enforceCallerIsRecentsOrHasPermission(java.lang.String,java.lang.String)"},
		{"android.content.PermissionChecker", "int checkPermissionForPreflight(android.content.Context,java.lang.String,int,int,java.lang.String)"},
		{"android.content.ContentProvider", "int checkPermissionAndAppOp(java.lang.String,java.lang.String,java.lang.String,android.os.IBinder)"},

		// TODO: Try to dynamically catch the following sink methods (although that might not be 100% possible due 
		//  to the semantic nature of those APIs)! I collected them by skimming throw non-classified methods and 
		//  filter the list manually!
		{"com.android.server.ConnectivityService", "boolean checkAnyPermissionOf(int,int,java.lang.String[])"},
		{"com.android.server.ConnectivityService", "boolean checkAnyPermissionOf(java.lang.String[])"},
		{"com.android.server.ConnectivityService", "void enforceAnyPermissionOf(java.lang.String[])"},
		{"com.android.server.net.NetworkPolicyManagerService", "void enforceAnyPermissionOf(java.lang.String[])"},
		{"com.android.server.biometrics.fingerprint.FingerprintService", "void checkPermission(java.lang.String)"},
		{"com.android.server.om.PackageManagerHelper", "void enforcePermission(java.lang.String,java.lang.String)"},
		{"com.android.server.net.NetworkStatsService", "void enforceAnyPermissionOf(java.lang.String[])"},
		{"com.android.server.accounts.AccountManagerService", "boolean checkPermissionAndNote(java.lang.String,int,java.lang.String[])"},
		{"com.android.server.accounts.AccountManagerService", "boolean isPermittedForPackage(java.lang.String,int,java.lang.String[])"},
		{"com.android.server.biometrics.face.FaceService", "void checkPermission(java.lang.String)"},
		{"android.os.storage.StorageManager", "boolean checkPermissionAndCheckOp(android.content.Context,boolean,int,int,java.lang.String,java.lang.String,int)"},
		{"android.net.NetworkStack", "void checkNetworkStackPermissionOr(android.content.Context,java.lang.String[])"},
		{"com.android.server.usage.UsageStatsService$BinderService", "boolean hasPermissions(java.lang.String,java.lang.String[])"},
		{"com.android.server.soundtrigger_middleware.SoundTriggerMiddlewareValidation", "void enforcePermission(java.lang.String)"},
		{"com.android.server.timezone.PermissionHelper", "void enforceCallerHasPermission(java.lang.String)"},
		{"com.android.server.wifi.p2p.WifiP2pServiceImpl", "void enforceAnyPermissionOf(java.lang.String[])"},
		{"com.android.server.wifi.WifiServiceImpl", "void enforceAnyPermissionOf(java.lang.String[])"},
		{"android.view.ViewRootImpl$W", "int checkCallingPermission(java.lang.String)"},
		{"android.permission.PermissionControllerService$1", "void enforceSomePermissionsGrantedToCaller(java.lang.String[])"},
		{"com.android.bluetooth.Utils", "boolean checkCallerHasFineLocation(android.content.Context,android.app.AppOpsManager,java.lang.String,java.lang.String,android.os.UserHandle)"},
		{"com.android.bluetooth.Utils", "boolean checkCallerHasCoarseLocation(android.content.Context,android.app.AppOpsManager,java.lang.String,java.lang.String,android.os.UserHandle)"},
		{"com.android.server.pm.CrossProfileAppsServiceImpl", "boolean isPermissionGranted(java.lang.String,int)"},
		{"com.android.server.vr.VrManagerService", "void enforceCallerPermissionAnyOf(java.lang.String[])"},
		{"com.android.server.companion.CompanionDeviceManagerService", "void updateSpecialAccessPermissionAsSystem(android.content.pm.PackageInfo)"},
		{"com.android.server.timezone.PackageManagerHelper", "boolean usesPermission(java.lang.String,java.lang.String)"},
		{"com.android.server.companion.CompanionDeviceManagerService", "boolean containsEither(java.lang.Object[],java.lang.Object,java.lang.Object)"},
		{"android.text.TextUtils", "boolean equals(java.lang.CharSequence,java.lang.CharSequence)"},
		{"java.util.Objects", "boolean equals(java.lang.Object,java.lang.Object)"},
		{"com.android.settings.applications.UsageAccessDetails", "boolean doesAnyPermissionMatch(java.lang.String,java.lang.String[])"},
		{"", ""},
		{"", ""},
		{"", ""}
	};
	
	// This whole list doesn't affect the percision of the analysis. It is just here to reduce the noise!
	public static final String[][] NONE_PERMISSION_CHECKS = {
		// Class doesn't matter!
		{"*", "void attachInterface(android.os.IInterface,java.lang.String)"},
		{"*", "int checkSelfPermission(android.content.Context,java.lang.String)"},
		{"*", "int w(java.lang.String,java.lang.String)"},
		{"*", "int e(java.lang.String,java.lang.String,java.lang.Throwable)"},
		{"*", "int wtf(java.lang.String,java.lang.String)"},
		{"*", "int w(java.lang.String,java.lang.String,java.lang.Throwable)"},
		{"*", "int e(java.lang.String,java.lang.String)"},
		{"*", "int i(java.lang.String,java.lang.String)"},
		{"*", "void w(java.lang.Object,java.lang.String,java.lang.Object[])"},
		
		{"android.content.Context", "int checkSelfPermission(java.lang.String)"},
		{"java.lang.IllegalStateException", "void"},
		{"java.lang.SecurityException", "void"},
		{"java.lang.IllegalArgumentException", "void"},
		{"android.os.Bundle", "void putParcelable(java.lang.String,android.os.Parcelable)"},
		{"android.os.Bundle", "android.os.Parcelable getParcelable(java.lang.String)"},
		{"android.os.Parcel", "void writeInterfaceToken(java.lang.String)"},
		{"android.os.Parcel", "void enforceInterface(java.lang.String)"},
		{"android.os.IBinder", "android.os.IInterface queryLocalInterface(java.lang.String)"},
		{"android.content.pm.PackageManager", "void grantRuntimePermission(java.lang.String,java.lang.String,android.os.UserHandle)"},
		{"android.content.pm.PackageManager", "void revokeRuntimePermission(java.lang.String,java.lang.String,android.os.UserHandle)"},
		{"android.content.Intent", "void"},
		{"android.os.Parcel", "void writeString(java.lang.String)"},
		{"android.content.Intent", "android.content.Intent putExtra(java.lang.String,java.lang.String)"},
		{"android.app.AppOpsManager", "java.lang.String permissionToOp(java.lang.String)"},
		{"android.os.Bundle", "void putParcelableList(java.lang.String,java.util.List)"},
		{"android.app.Activity", "void requestPermissions(java.lang.String[],int)"},
		{"android.preference.PreferenceFragment", "void requestPermissions(java.lang.String[],int)"},
		{"androidx.core.app.ActivityCompat", "boolean shouldShowRequestPermissionRationale(android.app.Activity,java.lang.String)"},
		{"java.lang.StringBuilder", "java.lang.StringBuilder append(java.lang.String)"},
		{"com.android.contacts.util.PermissionsUtil", "boolean hasPermission(android.content.Context,java.lang.String)"},
		{"com.android.permissioncontroller.permission.utils.Utils", "void"},
		{"android.app.Fragment", "void requestPermissions(java.lang.String[],int)"},
		{"android.app.AppOpsManager", "int permissionToOpCode(java.lang.String)"},
		{"android.content.Intent", "android.content.Intent setClassName(java.lang.String,java.lang.String)"},
		{"com.android.dialer.util.PermissionsUtil", "boolean isFirstRequest(android.content.Context,java.lang.String)"},
		{"android.app.Activity", "boolean shouldShowRequestPermissionRationale(java.lang.String)"},
		{"com.android.server.vr.VrManagerService", "boolean isPermissionUserUpdated(java.lang.String,java.lang.String,int)"},
		
		// The following cause a lot of imprecision and should be handled separately!
		{"android.content.ContentProvider", "void setReadPermission(java.lang.String)"},
		{"android.content.ContentProvider", "void setWritePermission(java.lang.String)"},
		{"com.android.internal.telephony.InboundSmsHandler", "void dispatchIntent(android.content.Intent,java.lang.String,java.lang.String,android.os.Bundle,android.content.BroadcastReceiver,android.os.UserHandle,int)"},
		{"android.app.IActivityManager", "int broadcastIntentWithFeature(android.app.IApplicationThread,java.lang.String,android.content.Intent,java.lang.String,android.content.IIntentReceiver,int,java.lang.String,android.os.Bundle,java.lang.String[],int,android.os.Bundle,boolean,boolean,int)"},
		{"com.android.server.am.ActivityManagerService", "int broadcastIntentLocked(com.android.server.am.ProcessRecord,java.lang.String,java.lang.String,android.content.Intent,java.lang.String,android.content.IIntentReceiver,int,java.lang.String,android.os.Bundle,java.lang.String[],int,android.os.Bundle,boolean,boolean,int,int,int,int,int)"},
		{"com.android.server.am.ActivityManagerService", "int broadcastIntentInPackage(java.lang.String,java.lang.String,int,int,int,android.content.Intent,java.lang.String,android.content.IIntentReceiver,int,java.lang.String,android.os.Bundle,java.lang.String,android.os.Bundle,boolean,boolean,int,boolean)"},

		
		// Broadcast senders!
		{"android.content.Context", "void sendBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String)"},
		{"android.content.Context", "void sendBroadcast(android.content.Intent,java.lang.String)"},
		{"android.content.Context", "void sendBroadcast(android.content.Intent,java.lang.String,android.os.Bundle)"},
		{"android.content.Context", "void sendBroadcastWithMultiplePermissions(android.content.Intent,java.lang.String[])"},
		{"android.content.Context", "void sendBroadcastAsUserMultiplePermissions(android.content.Intent,android.os.UserHandle,java.lang.String[])"},
		{"android.content.Context", "void sendBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String,int)"},
		{"android.content.Context", "void sendOrderedBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String,int,android.os.Bundle,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)"},
		{"android.content.Context", "void sendBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String,android.os.Bundle)"},
		{"android.content.Context", "void sendOrderedBroadcast(android.content.Intent,java.lang.String,java.lang.String,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)"},
		{"android.content.Context", "void sendOrderedBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String,int,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)"},
		{"android.content.Context", "void sendOrderedBroadcast(android.content.Intent,java.lang.String)"},
		{"android.content.Context", "void sendOrderedBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)"},
		{"android.app.PendingIntent", "void send(android.content.Context,int,android.content.Intent,android.app.PendingIntent$OnFinished,android.os.Handler,java.lang.String,android.os.Bundle)"},
		{"com.android.internal.app.AlertActivity", "void sendBroadcast(android.content.Intent,java.lang.String)"},
		{"com.android.bluetooth.btservice.AdapterService", "void sendBroadcastMultiplePermissions(android.content.Intent,java.lang.String[])"},

		// Broadcast receivers!
		{"android.content.Context", "android.content.Intent registerReceiver(android.content.BroadcastReceiver,android.content.IntentFilter,java.lang.String,android.os.Handler)"},
		{"android.content.Context", "android.content.Intent registerReceiverAsUser(android.content.BroadcastReceiver,android.os.UserHandle,android.content.IntentFilter,java.lang.String,android.os.Handler)"},
		{"android.content.Context", "android.content.Intent registerReceiverForAllUsers(android.content.BroadcastReceiver,android.content.IntentFilter,java.lang.String,android.os.Handler)"},
		{"com.android.server.timezone.PackageManagerHelper", "boolean receiverRegistered(android.content.Intent,java.lang.String)"},
		
		{"", ""},
		{"", ""},
		{"", ""},
		{"", ""},
		{"", ""},
		{"", ""},
	};
	
	public static final String[][] EXCLUDED_METHODS = {
			{"*", "void <clinit>()"},
			{"", "<init>()"},
			{"com.android.permissioncontroller.permission.utils.Utils", "boolean isPermissionIndividuallyControlled(android.content.Context,java.lang.String)"},
		};
	
	public static final List<String> EXCLUDED_JARS = Arrays.asList(new String[] {
			"core-oj.jar", 					// causes error while decompiling! @TODO: FixMe?
			"vr.jar",						// error @samsung
			"knoxsdk.jar",					// error @samsung
			"android.test.runner.jar",  	// irrelevant
			"android.test.mock.jar",		// irrelevant
			"android.test.base.jar",		// irrelevant
			"org.chromium.net.cronet.jar"	// irrelevant
		}
	);
	
	public static final int SINK = 1;
	public static final int NOT_SINK = 2;
	public static final int UNKNOWN = -1;
	
	public static final String SINK_VALUE = "SINK";
	public static final String NOT_SINK_VALUE = "NOT-SINK";
	public static final String UNKNOWN_VALUE = "N/A";
}
