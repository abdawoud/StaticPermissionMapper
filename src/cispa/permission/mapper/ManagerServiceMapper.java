package cispa.permission.mapper;

import org.json.JSONObject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import cispa.permission.mapper.analysis.ApiFileMapping;
import cispa.permission.mapper.analysis.BinderInterfaceAnalysis;
import cispa.permission.mapper.analysis.GlobalPermissionMappingAnalysis;
import cispa.permission.mapper.analysis.ManagerApisPermissionAnalysis;
import cispa.permission.mapper.analysis.ServiceApisAnalysis;
import cispa.permission.mapper.models.ParsedMethod;
import cispa.permission.mapper.models.SinkMethod;
import cispa.permission.mapper.utils.AnalysisHelper;
import cispa.permission.mapper.utils.Constants;
import cispa.permission.mapper.utils.Helper;
import cispa.permission.mapper.utils.IOHelper;
import cispa.permission.mapper.utils.StringParser;
import soot.Body;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.UnitBox;
import soot.UnitPatchingChain;
import soot.Value;
import soot.ValueBox;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.util.Chain;

public class ManagerServiceMapper {
	
	// TODO: refactor this!
	public static final List<String> nonePermissionSinks = new ArrayList<>();
	public static final List<String> permissionSinks = new ArrayList<>();
	public static final List<String> noneClassifiedSinks = new ArrayList<>();

	public static void main(String[] args) throws IOException {
		// 3 hrs 34

		// The following methods are dependent on each others as one's output is the input of the next one!
		
		// Get all binder interfaces defined in all jar and dex files!
		new BinderInterfaceAnalysis().execute();
		
		// Create a global method to permission mapping starting from permission strings (verifies sinks using 
		//  forward analysis and builds the mapping using backward analysis). This is too much result for 
		//  permission mapping and over approximates
		new GlobalPermissionMappingAnalysis().execute();
		
		// Reduce the previous output to only the service APIs using the over approximated results from above :(
		new ServiceApisAnalysis().execute();
		
		// Naively map proxy APIs to the managers that use them 
		new ApiFileMapping().execute();
		
		// Complete the circuit and map the the proxy APIs to the manager APIs!
		new ManagerApisPermissionAnalysis().execute();
	}

}