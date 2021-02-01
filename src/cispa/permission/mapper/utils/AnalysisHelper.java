package cispa.permission.mapper.utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import cispa.permission.mapper.ManagerServiceMapper;
import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.UnitBox;
import soot.Value;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;

public class AnalysisHelper {
	
	public static String translateClassification(int cls) {
		switch (cls) {
		case Constants.UNKNOWN:
			return Constants.UNKNOWN_VALUE;
		case Constants.SINK:
			return Constants.SINK_VALUE;
		case Constants.NOT_SINK:
			return Constants.NOT_SINK_VALUE;
		default:
			return null;
		}
	}
	
	@SuppressWarnings("finally")
	public static int getPermissionParameterIndex(String statement) {
		int index = -1;
		try {
			String[] params = StringParser.getParametersFromMethodInvocation(statement);
			for (int i = 0; i < params.length; i++) {
				if (params[i].contains(".permission.") && params[i].contains("\"")) {
					index = i;
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			return index;
		}
	}
	
	@SuppressWarnings("finally")
	public static int getParameterPosition(String statement, String parameterName) {
		int index = -1;
		try {
			String[] params = StringParser.getParametersFromMethodInvocation(statement);
			for (int i = 0; i < params.length; i++) {
				if (params[i].equals(parameterName)) {
					index = i;
					break;
				}
			}
		} catch (Exception e) {
		} finally {
			return index;
		}
	}
	
	public static List<Unit> getInstructionsThatUseVariable(Collection<Unit> units, String parameterName) {
		List<Unit> qualifedUnits = new ArrayList<>();
		for (Unit u : units) {
			if (u.toString().contains("invoke " + parameterName + ".<")) {
				qualifedUnits.add(u);
			}
		}
		return qualifedUnits;
	}
	
	public static List<Unit> getVariableAssignments(SootMethod method, String parameterName) {
		Body body = method.retrieveActiveBody();
		List<Unit> qualifedInstructions = new ArrayList<>();
		for (UnitBox ub : body.getAllUnitBoxes()) {
			Unit u = ub.getUnit();
			if (u.toString().contains(parameterName + " = ")) {
				qualifedInstructions.add(u);
			}
		}
		return qualifedInstructions;
	}
	
	public static int checkSinkForFirstDegreeMethods(SootMethod sootMethod, String sink, int permParamIndex,
			List<String> forwardMethodUnstructured, boolean calledForVariable) {	
		int res = Constants.UNKNOWN;
		for (String sm : forwardMethodUnstructured) {
			sm = sm.split("\\|")[1];
			res = classifyPermissionSinkInner(sm, sink, calledForVariable);
			if (res != Constants.UNKNOWN) {
				break;
			}
		}
		
		return res;
	}
	
	public static int classifyPermissionSink(String statement, int permParamIndex, 
			String originalSink, boolean calledForVariable, JimpleBasedInterproceduralCFG jbicfg) {
		String[] parsedMethod = StringParser.parseMethodFromInvocationStatment(statement);
		String sink = parsedMethod[0];
		
		int classification = classifyPermissionSinkInner(statement, originalSink, calledForVariable);
		
		if (classification == Constants.UNKNOWN && !ManagerServiceMapper.noneClassifiedSinks.contains(sink)) {
			String sinkClass = parsedMethod[1];
			String sinkMethod = parsedMethod[2];
			SootClass sootClass = Scene.v().getSootClass(sinkClass);
			
			String methodSignature = StringParser.asMethodSignature(sinkClass, sinkMethod);
			SootMethod sootMethod = getSootMethodBySignature(sootClass, methodSignature);
			
			List<String> forwardMethodUnstructured = new ArrayList<>();
			forwardTracing(sootMethod, permParamIndex, forwardMethodUnstructured, jbicfg);
			
			classification = checkSinkForFirstDegreeMethods(sootMethod, sink, permParamIndex, forwardMethodUnstructured, calledForVariable);
						
			// Check Super classes for the method!
			if (classification == Constants.UNKNOWN) {
				ArrayList<String> superClasses = new ArrayList<>();
				getSuperClasses(Scene.v().getSootClass(sinkClass), superClasses);
				
				for (String sc : superClasses) {
					SootClass superClass = Scene.v().getSootClass(sc);
					for (String fm : forwardMethodUnstructured) {
						String[] tokens = fm.split("\\|");
						fm = tokens[1];
						permParamIndex = Integer.parseInt(tokens[0]);
						SootMethod superMethod = getSootMethodBySignature(superClass, "<" + superClass + ": " + fm.split(": ")[1]);
						if (superMethod == null)
							continue;
						forwardMethodUnstructured = new ArrayList<>();
						forwardTracing(superMethod, permParamIndex, forwardMethodUnstructured, jbicfg);
						classification = checkSinkForFirstDegreeMethods(superMethod, sink, permParamIndex, forwardMethodUnstructured, calledForVariable);

						if (classification != Constants.UNKNOWN) {
							break;
						}
					}
				}
			}
			
			if (classification == Constants.UNKNOWN) {
				ManagerServiceMapper.noneClassifiedSinks.add(sink);
				System.out.println("[-] " + sink);
			}
		}
			
		return classification;
	}
	
	private static int classifyPermissionSinkInner(String statement, String originalSink, boolean calledForVariable) {
		int classification = Constants.UNKNOWN;
		String[] parsedStatement = StringParser.parseMethodFromInvocationStatment(statement);
		
		if (parsedStatement == null) {
			return classification;
		}
		
		String sink = parsedStatement[0];
		String sinkClass = parsedStatement[1];
		String sinkMethod = parsedStatement[2];
		
		SootClass sootClass = Scene.v().getSootClass(sinkClass);
		
		ArrayList<String> superClasses = new ArrayList<>();
		getSuperClasses(sootClass, superClasses);
		
		String sinkTemp = sink;

		sink = (originalSink != null)? originalSink : sink;
		
		if (originalSink == null || (originalSink != null && calledForVariable)) {
			if ((originalSink != null && calledForVariable)) {
				sink = (originalSink != null)? originalSink : sink;
			}
			for (String[] noneSinkInfo : Constants.NONE_PERMISSION_CHECKS) {
				if ((superClasses.contains(noneSinkInfo[0]) || noneSinkInfo[0].equals("*")) && 
						noneSinkInfo[1].equals(sinkMethod) && !ManagerServiceMapper.nonePermissionSinks.contains(sink)) {
					ManagerServiceMapper.nonePermissionSinks.add(sink + " because of " + sinkTemp);
					System.out.println("[NoneSink] " + sink + " because of " + sinkTemp);
					classification = Constants.NOT_SINK;
					break;
				} else if (ManagerServiceMapper.nonePermissionSinks.contains(sink)) {
					classification = Constants.NOT_SINK;
				}
			}
		}
				
		sink = sinkTemp;
		for (String[] sinkInfo : Constants.PERMISSION_CHECKS) {
			if ((superClasses.contains(sinkInfo[0]) || sinkInfo[0].equals("*")) && 
					sinkInfo[1].equals(sinkMethod) && !ManagerServiceMapper.permissionSinks.contains(sink)) {
				ManagerServiceMapper.permissionSinks.add(sink);
				System.out.println("[Sink] " + sink);
				classification = Constants.SINK;
				break;
			} else if (ManagerServiceMapper.permissionSinks.contains(sink)) {
				classification = Constants.SINK;
			}
		}
		
		return classification;
	}
	
	/*
	 * Recursive method to get all super classes of a class
	 */
	public static ArrayList<String> getSuperClasses(SootClass sootClass, ArrayList<String> superClasses) {
		// First iteration. Make sure the original class exists and then check for parents.
		if (superClasses.size() == 0)
			superClasses.add(sootClass.getName());
		
		if (sootClass.getName().contains("java.lang.Object"))
			return superClasses;
		
		SootClass superClass = sootClass.getSuperclass();
		
		if (superClass == null)
			return superClasses;
		
		superClasses.add(superClass.getName());
		return getSuperClasses(superClass, superClasses);
	}
	
	public static void forwardTracing(SootMethod sootMethod, int permissionIndex, 
			List<String> forwardMethodUnstructured, JimpleBasedInterproceduralCFG jbicfg) {
		try {
			sootMethod.retrieveActiveBody();
		} catch (Exception e) {
			if (sootMethod != null) {
				forwardMethodUnstructured.add(permissionIndex + "|" + sootMethod.getSignature());
			}
			return;
		}
		
		for (Unit n : jbicfg.getCallsFromWithin(sootMethod)) {
			Value nextParamValue;
			try {
				nextParamValue = sootMethod.getActiveBody().getParameterLocal(permissionIndex);
			} catch (Exception e) {
				return;
			}
			int nextParamPosition = AnalysisHelper.getParameterPosition(n.toString(), nextParamValue.toString());
			
			if (nextParamPosition > -1) {
				String[] parsedUnit = StringParser.parseMethodFromInvocationStatment(n.toString());
				SootClass nextSootClass = Scene.v().getSootClass(parsedUnit[1]);
				SootMethod nextSootMethod = getSootMethodBySignature(nextSootClass, 
						StringParser.asMethodSignature(parsedUnit[1], parsedUnit[2]));
				if (nextSootMethod == null) {
					forwardMethodUnstructured.add(nextParamPosition + "|" + "<" + parsedUnit[1] + ": " + parsedUnit[2] + ">");
					return;
				}
				forwardMethodUnstructured.add(nextParamPosition + "|" + nextSootMethod.toString());
				forwardTracing(nextSootMethod, nextParamPosition, forwardMethodUnstructured, jbicfg);
			}
		}
	}
	
	public static SootMethod getSootMethodBySignature(SootClass clazz, String methodSignature) {
		for (SootMethod m : clazz.getMethods()) {
			if (m.getSignature().equals(methodSignature)) {
				return m;
			}
		}
		return null;
	}
	
	public static String handleEqualsInstructions(SootMethod method, Unit u) {
		String componentType = null;
		if (u.toString().contains("java.lang.String: boolean equals(java.lang.Object)")) {
			List<Unit> usingInstructions = AnalysisHelper.getVariableAssignments(method, u.toString().split("\\>\\(")[1].split("\\)")[0]);
			for (Unit v : usingInstructions) {
				if (v.toString().contains("<android.content.pm.ActivityInfo: java.lang.String permission>")) {
					componentType = "activity";
					break;
				} else if (v.toString().contains("<android.content.pm.ServiceInfo: java.lang.String permission>")) {
					componentType = "service";
					break;
				} else if (v.toString().contains("<android.content.pm.ProviderInfo: java.lang.String readPermission>")) {
					componentType = "provider-read";
					break;
				} else if (v.toString().contains("<android.content.pm.ProviderInfo: java.lang.String writePermission>")) {
					componentType = "provider-write";
					break;
				}  else if (v.toString().contains("<android.content.pm.ApplicationInfo: java.lang.String permission>")) {
					componentType = "application";
					break;
				} else if (v.toString().contains("java.lang.String permission>")) {
					componentType = "unknown";
					break;
				} else {
					return null;
				}
			}
		}
		
		return componentType;
	}
	
	public static boolean isExcludedMethod(SootClass clazz, SootMethod method) {
		boolean excluded = false;
		for (String[] em : Constants.EXCLUDED_METHODS) {
			boolean skip = em[0].equals("*")? true : em[0].equals(clazz.getName());
			if (skip && em[1].equals(method.getSubSignature())) {
				excluded = true;
				break;
			}
		}
		return excluded;
	}
	
}
