package cispa.permission.mapper.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import cispa.permission.mapper.models.ParsedMethod;
import cispa.permission.mapper.models.SinkMethod;
import cispa.permission.mapper.utils.AnalysisHelper;
import cispa.permission.mapper.utils.Constants;
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
import soot.UnitPatchingChain;
import soot.ValueBox;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.util.Chain;

public class GlobalPermissionMappingAnalysis {
	
	private static final HashMap<String, ArrayList<String>> globalMapping = new HashMap<String, ArrayList<String>>();
	
	public GlobalPermissionMappingAnalysis() {}
		
	public void execute() throws IOException {
		File[] files = IOHelper.getDexFilePaths(new String[] {}, new String[] {});
		
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
		
		final BufferedWriter componentPermissionsWriter = IOHelper.getWriter(Constants.COMPONENT_PERMISSIONS_FILE, true);
				
		for (File dexFile : files) {
			final BufferedWriter globalMappingWriter = IOHelper.getWriter(Constants.GLOBAL_MAPPING_FILE, false);

			System.out.println(dexFile.getAbsolutePath() + " " + dexFile.getName());
			
			sootOptions[1] = dexFile.getAbsolutePath();
			
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.ManagerServiceMapper", new SceneTransformer() {

				@Override
				protected void internalTransform(String phaseName, Map options) {
					System.out.println("Started the transformation!");
					// Call hierarchy analysis - not sure if it's needed of if used correctly! documentation doesn't help!
					// CHATransformer.v().transform();
					// Scene.v().loadNecessaryClasses();
					// Scene.v().loadDynamicClasses();
					
					// For some reason, an edge might exist in one graph but not the other!
					//  I play it safe and get the edge from both graph and risk duplications (+overhead)
					final CallGraph cg = Scene.v().getCallGraph();
					JimpleBasedInterproceduralCFG jbicfg = new JimpleBasedInterproceduralCFG();
										
					Chain<SootClass> classes = Scene.v().getApplicationClasses();
					System.out.println(classes.size());
					
					int index = 0;
					for (SootClass clazz : classes) {
						if (index % 100 == 0)
							System.out.println(index + "/" + classes.size());
						index++;
						try {
							for (SootMethod method : clazz.getMethods()) {
								if (AnalysisHelper.isExcludedMethod(clazz, method)){
									continue;
								}
								
								boolean isQualifiedSink = false;
								
								// Get method's body if it has one, otherwise skip it as it is already disqualified!
								try {
									method.retrieveActiveBody();
								} catch (Exception e) {
									continue;
								}
								
								String appendable = "";								
								appendable += getMethodDetails(dexFile, method, clazz, jbicfg);
								
								List<String> noDups = new ArrayList<>();
								
								Iterator<Edge> outs = cg.edgesOutOf(method);
								while(outs.hasNext()) {
									try {
										Edge edge = outs.next();
										String edgeString = edge.toString();
										if (StringParser.hasPermissionSomewhere(edgeString)) {
											String edgeTrimmed = edgeString.split(" edge: ")[1].split(" in <")[0];
											int permParamIndex =  AnalysisHelper.getPermissionParameterIndex(edgeTrimmed);
											// Forward analysis to classify the sink!
											int cls = AnalysisHelper.classifyPermissionSink(edgeTrimmed, permParamIndex, null, false, jbicfg);
											if (cls == Constants.SINK) {
												noDups.add(edgeTrimmed);
												reportSinkMethod(method, edgeTrimmed);
												
												populateCallers(edgeTrimmed, dexFile, method, jbicfg);
												
												isQualifiedSink = true;
											}
										}
									} catch (Exception e) {
										// just in case something terrible happened!
										e.printStackTrace();
									}
								}
								Collection<Unit> callsFromMethod = jbicfg.getCallsFromWithin(method);
								for (Unit u : callsFromMethod) {
									try {
										String unitStr = u.toString();
										if (StringParser.hasPermissionSomewhere(unitStr)) {
											for (String d : noDups) {
												if (d.contains(unitStr))
													continue;
											}
											int permParamIndex =  AnalysisHelper.getPermissionParameterIndex(unitStr);
											int cls = AnalysisHelper.classifyPermissionSink(unitStr, permParamIndex, null, false, jbicfg);
											if (cls == Constants.SINK) {
												reportSinkMethod(method, unitStr);
												
												populateCallers(unitStr, dexFile, method, jbicfg);
												
												isQualifiedSink = true;
											}
										}
									} catch (Exception e) {
										// just in case something terrible happened!
										e.printStackTrace();
									}
								}
								
								Body methodBody = method.retrieveActiveBody();
								UnitPatchingChain methodUnits = methodBody.getUnits();
								for(Unit unit : methodUnits) {
									if (StringParser.hasPermissionSomewhere(unit.toString()) && 
											!unit.toString().contains("invoke")) {

										if (unit.getDefBoxes().size() > 1) {
											throw new Exception("Just to make sure assumption holds!");
										}
										
										boolean usedAsParameter = false;

										for (ValueBox vb : unit.getDefBoxes()) {
											for (Unit sm : jbicfg.getCallsFromWithin(method)) {
												String paramName = vb.getValue().toString().split("\\[")[0];
												int nextParamPosition = AnalysisHelper.getParameterPosition(sm.toString(), paramName);
												if (nextParamPosition > -1) {
													int cls = AnalysisHelper.classifyPermissionSink(sm.toString(), nextParamPosition, unit.toString(), true, jbicfg);
													if (cls == Constants.SINK) {
														reportSinkMethod(method, sm.toString());
														
														populateCallers(sm.toString(), dexFile, method, jbicfg);
														appendable += sm.toString() + "\n";
														
														isQualifiedSink = true;
													}
													usedAsParameter = true;
												}
											}
										}
										if (!usedAsParameter) {
											String componentType = null;
											for (ValueBox vb : unit.getDefBoxes()) {
												List<Unit> instructions = AnalysisHelper.getInstructionsThatUseVariable(jbicfg.getCallsFromWithin(method), 
														vb.getValue().toString().split("\\[")[0]);
												for (Unit u : instructions) {
													componentType = AnalysisHelper.handleEqualsInstructions(method, u);
													if (componentType != null)
														break;
												}
												if (componentType != null)
													break;
												
											}
											if (componentType != null) {
												appendable += "[INSTRUCTION][" + AnalysisHelper.translateClassification(Constants.SINK) + "][" + componentType + "] " + unit.toString() + "\n";
											}
										}
										
//										if (!usedAsParameter && !isComponentPermission) {
//											appendable += "[INSTRUCTION][" + AnalysisHelper.translateClassification(Constants.UNKNOWN) + "]" + unit.toString() + "\n";
//										}
									}
								}
								
								if (isQualifiedSink) {
									componentPermissionsWriter.append(appendable + "\n");
									componentPermissionsWriter.flush();
								}
							}
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					
					Gson gson = new GsonBuilder().setPrettyPrinting().create();
					try {
						globalMappingWriter.write(gson.toJson(globalMapping));
						globalMappingWriter.close();
					} catch (IOException e) {
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
		
//		for (String noneSink : nonePermissionSinks) {
//			sinks.append("[NoneSink+]" + noneSink + "\n");
//		}
//		
//		for (String sink : permissionSinks) {
//			sinks.append("[Sink+]" + sink + "\n");
//		}
//		
//		for (String sink : noneClassifiedSinks) {
//			sinks.append("[-]" + sink + "\n");
//		}

		componentPermissionsWriter.close();
	}
	
	private ArrayList<String> getMethodAsProxyInAllSuperClasses(SootMethod method) {
		ArrayList<String> methods = new ArrayList<>();
		ArrayList<String> superClasses = new ArrayList<>();
		AnalysisHelper.getSuperClasses(method.getDeclaringClass(), superClasses);
		for (String cls : superClasses) {
			if (cls.equals("java.lang.Object"))
				continue;
			String methodSignature = "<" + cls + "$Proxy: " + method.toString().split(": ")[1];
			methods.add(methodSignature);
		}
		return methods;
	}
	
	private void getAllCallers(JimpleBasedInterproceduralCFG jbicfg, SootMethod method, ArrayList<String> allCallers, File dexFile) {
		if (method == null)
			return;
		
		Collection<Unit> callers = jbicfg.getCallersOf(method);
		if (callers.size() == 0 || callers.size() >= 50 || allCallers.size() >= 500) {
			return;
		}

		for (Unit caller : callers) {
			SootMethod sm = jbicfg.getMethodOf(caller);
			if (isKnownMethod(sm.toString())) {
				continue;
			}
//			if (!sm.isPublic()) {
//				continue;
//			}
			
			// Naive approach to avoid endless recursion!
			if (allCallers.contains(sm.toString())) {
				continue;
			}
			allCallers.add(sm.toString());

			ArrayList<String> proxyMethods = getMethodAsProxyInAllSuperClasses(sm);
			for (String m : proxyMethods) {
				allCallers.add(m.toString());
			}
			
			getAllCallers(jbicfg, sm, allCallers, dexFile);
		}
	}
	
	private boolean isKnownMethod(String method) {
		String[] endlessMethods = {
				"void run()",
				"java.lang.Thread: void start()",
				"boolean postDelayed(java.lang.Runnable,long)",
				"boolean post(java.lang.Runnable)",
				"void accept(java.lang.Object)",
				"boolean postAtTime(java.lang.Runnable,long)",
				"boolean postAtFrontOfQueue(java.lang.Runnable)",
				"void execute(java.lang.Runnable)",
				"doSendBroadcast",
				"boolean test(java.lang.Object)",
				"com.android.server.wm.ActivityStarter: int execute()",
				"com.android.server.am.NativeCrashListener: void start()",
				"android.os.Handler: boolean postAtTime(java.lang.Runnable,java.lang.Object,long)",
				"int update(com.android.providers.media.DatabaseHelper,android.content.ContentValues,java.lang.String,java.lang.String[])"
				
		};
		for (String em : endlessMethods) {
			if (method.contains(em))
				return true;
		}
		return false;
	}
	
	private String getMethodDetails(File dexFile, SootMethod method, SootClass clazz, 
			JimpleBasedInterproceduralCFG jbicfg) throws IOException {
		ArrayList<String> proxyMethods = getMethodAsProxyInAllSuperClasses(method);
		
		return "\n\n>>>>>>>>>>> " + dexFile.getAbsolutePath() + " --- " + method.getSignature() +
				" in: " + jbicfg.getCallersOf(method).size() +
				" out: " + jbicfg.getCallsFromWithin(method).size() + "\n";
	}
	

	
	private void populateGlobalMapping(SinkMethod method) {
		populateGlobalMapping(method.getMethod().toString(), method.getPermissions());
	}
	
	private void populateGlobalMapping(String method, List<String> permissions) {
		method = method.replaceAll("<", "").replaceAll(">", "");
		if (!globalMapping.containsKey(method)) {
			globalMapping.put(method, new ArrayList<String>());
		}

		ArrayList<String> tmp = globalMapping.get(method);
		for (int i = 0; i < permissions.size(); i++) {
			if (!tmp.contains(permissions.get(i)))
				tmp.add(permissions.get(i));
		}
		
		// ugly workaround until I fix the underlying problem!
		if (tmp.size() <= 7)
			globalMapping.put(method, tmp);
	}	
	
	private void populateCallers(String statement, File dexFile, SootMethod method, JimpleBasedInterproceduralCFG jbicfg) {
		List<String> intermediatePermissions = StringParser.getMethodAndPermissions(statement).getPermissions();
		ArrayList<String> allCallers = new ArrayList<>();
		getAllCallers(jbicfg, method, allCallers, dexFile);
		for (String caller : allCallers) {
			populateGlobalMapping(caller, intermediatePermissions);
		}
	}
	
	private void reportSinkMethod(SootMethod method, String statement) {
		ParsedMethod parsedMethod = StringParser.getMethodAndPermissions(statement);
		SinkMethod sinkMethod = new SinkMethod(method, parsedMethod.getPermissions());
		populateGlobalMapping(sinkMethod);
		for (String p : getMethodAsProxyInAllSuperClasses(method)) {
			populateGlobalMapping(p, parsedMethod.getPermissions());
		}
	}
}
