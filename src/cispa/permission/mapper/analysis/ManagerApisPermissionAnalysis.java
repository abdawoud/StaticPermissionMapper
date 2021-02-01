package cispa.permission.mapper.analysis;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import cispa.permission.mapper.utils.AnalysisHelper;
import cispa.permission.mapper.utils.Constants;
import cispa.permission.mapper.utils.Helper;
import cispa.permission.mapper.utils.IOHelper;
import soot.Body;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.util.Chain;

public class ManagerApisPermissionAnalysis {

	public ManagerApisPermissionAnalysis() {}

	public void execute() throws IOException {
		File[] files = IOHelper.getDexFilePaths(new String[] {}, new String[] {"services.jar", "services_classes.cdex.dex", "services_classes2.cdex.dex"});

		String[] sootOptions = {
			"-process-dir", "",
			"-w",
			"-android-jars", Constants.ANDROID_JARS, 
			"-v", 
			"-src-prec", "apk",
//			"-f", "jimple",
//			"-keep-line-number",
//			"-output-dir", Constants.OUTPUT, 
			"-process-multiple-dex", 
			"-search-dex-in-archives",
			"-allow-phantom-refs",
			"-ignore-classpath-errors", 
			"-ignore-resolution-errors",
			"-ignore-resolving-levels"
		};

		BufferedReader br = IOHelper.getReader(Constants.SERVICE_MAPPING_FILE);
		JsonObject serviceMapping = new JsonParser().parse(br).getAsJsonObject();
		Set<String> apis = serviceMapping.keySet();
		List<String[]> apisFormatted = new ArrayList<String[]>();
		
		for (String api : apis) {
			String[] parts = api.split(": ");
			String clazz = parts[0].replace("$Stub$Proxy", "");
			apisFormatted.add(new String[] {api, clazz + ": " + parts[1]});
		}
		
		
		br = IOHelper.getReader(Constants.PROXY_TO_FILE_MAPPING_FILE);
		JsonObject fileMapping = new JsonParser().parse(br).getAsJsonObject();
		Set<String> apisForFiles = fileMapping.keySet();
		List<String> classesToLoad = new ArrayList<String>();
	
		for (String api : apisForFiles) {
			for (JsonElement je : fileMapping.getAsJsonArray(api)) {
				String file = je.getAsString();
				if (!classesToLoad.contains(file))
					classesToLoad.add(je.getAsString().split(".jimple")[0]);
			}
		}
		
		HashMap<String, List<String>> managerMapping = new HashMap<>();
		
		for (File dexFile : files) {
			BufferedWriter managerMappingWriter = IOHelper.getWriter(Constants.MANAGER_MAPPING_FILE, false);

			System.out.println(dexFile.getAbsolutePath() + " " + dexFile.getName());
			sootOptions[1] = dexFile.getAbsolutePath();
			
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.ManagerServiceMapper", new SceneTransformer() {

				@Override
				protected void internalTransform(String phaseName, Map options) {
					JimpleBasedInterproceduralCFG jbicfg = new JimpleBasedInterproceduralCFG();
					
					Chain<SootClass> classes = Scene.v().getApplicationClasses();
					System.out.println(classes.size());
					
					int index = 0;
					for (SootClass clazz : classes) {
						if (index % 1000 == 0)
							System.out.println(index + "/" + classes.size());
						index++;
						
						if (!classesToLoad.contains(clazz.getName())) {
							continue;
						}
						
						try {							
							for (SootMethod method : clazz.getMethods()) {
								if (AnalysisHelper.isExcludedMethod(clazz, method)){
									continue;
								}
								
								// Make sure method's active body is present if it has one in the first place
								try {
									method.retrieveActiveBody();
								} catch (Exception e) {
									continue;
								}
								Body body = method.getActiveBody();
								String methodSignature = method.getSignature().replaceAll("<", "").replaceAll(">", "");

								for (String[] pair : apisFormatted) {
									if (body.toString().contains(pair[1]) && !methodSignature.contains("$Stub$Proxy")) {
										List<String> perms = Helper.getJsonArrayAsList(serviceMapping.getAsJsonArray(pair[0]));
										if (perms.size() > 0 && !perms.contains("android.permission.INTERNET")) {
											System.out.println(methodSignature + " >> " + perms);
											managerMapping.put(methodSignature, perms);
											Collection<Unit> callers = jbicfg.getCallersOf(method);
											for (Unit caller : callers) {
												SootMethod callerMethod = jbicfg.getMethodOf(caller);
												if (callerMethod.isPublic() && 
														!method.toString().equals(callerMethod.toString()) && 
														!method.toString().contains("$Stub$Proxy") &&
														!perms.contains("android.permission.INTERNET")) {
													String sig = callerMethod.getSignature().replaceAll("<", "").replaceAll(">", "");
													System.out.println("+" + sig + " >> " + perms);
													managerMapping.put("+" + sig, perms);
												}
											}
										}
									}
								}
								
							}
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					
					Gson gson = new GsonBuilder().setPrettyPrinting().create();
					try {
						managerMappingWriter.write(gson.toJson(managerMapping));
						managerMappingWriter.close();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}));
			try {
				soot.options.Options.v().setPhaseOption("cg", "all-reachable:true");
				soot.Main.main(sootOptions);
				soot.G.reset();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
	}
}
