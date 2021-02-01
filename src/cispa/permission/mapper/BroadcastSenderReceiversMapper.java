package cispa.permission.mapper;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import cispa.permission.mapper.utils.Constants;
import soot.Body;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.UnitBox;
import soot.ValueBox;
import soot.grimp.internal.ExprBox;
import soot.jimple.internal.ImmediateBox;
import soot.jimple.internal.InvokeExprBox;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JimpleLocalBox;
import soot.options.Options;
import soot.util.Chain;

public class BroadcastSenderReceiversMapper {

	private static final String HOME = System.getProperty("user.home");
	private static final String OUTPUT = HOME + "/Desktop/resources/jimple";
	private static final String DEXES_FOLDER = HOME + "/Desktop/resources/dexes";
	private static final String ANDROID_JARS = HOME + "/Android/Sdk/platforms/";
	
	private static final String INTENT_CLASS = "android.content.Intent";
	private static final String INTENT_FILTER_CLASS = "android.content.IntentFilter";
	private static final String STRING_CLASS = "java.lang.String";
	private static final String STRING_ARRAY_CLASS = STRING_CLASS + "[]";

	@SuppressWarnings("serial")
	private final static List<String> sendBroadcastMethods = new ArrayList<String>() {{
		add(" sendOrderedBroadcastAsUser("); // 8 - 2 | 9 - [3,4appops] | 10 - [3,4appops]
		add(" sendOrderedBroadcast("); //2 - 2 | 7 - 2 | 8 - [2, 3appops] | 9 - [2, 3appops]
		add(" sendBroadcast("); //2 - 2 | 3 - 2 | 3 - [2,3 appops]
		add(" sendBroadcastMultiplePermissions("); //2 - 2
		add(" sendBroadcastAsUser("); //3 - 3 | 4 - [3, 4appops]
		add(" sendBroadcastAsUserMultiplePermissions("); //3 - 3
	}};
	
	@SuppressWarnings("serial")
	private final static List<String> registerBroadcastMethods = new ArrayList<String>() {{
		add(" registerReceiver("); //4 - 3 | 5 - 3 | 7 - 5
		add(" registerReceiverAsUser("); //5 - 4
		add(" registerReceiverForAllUsers("); //4 - 3 | 
		//add(" registerReceiverWithFeature("); //8 - 6
	}};
	
	@SuppressWarnings("serial")
	private final static List<String> setActionMethods = new ArrayList<String>() {{
		add("setAction(java.lang.String)");
		add("<init>(java.lang.String)");
	}};
	
	private static boolean isInitializationOf(Unit u, String type) {
		for (ValueBox ub : u.getUseBoxes()) {
			if (ub.toString().contains("LinkedRValueBox(new " + type)) {
				return true;
			}
		}
		return false;
	}
	
	private static String getInitializationStatement(Body mehtodBody, ValueBox vb, String type) {
		List<Unit> bodyReversed = new ArrayList<Unit>();
		for (Unit unit : mehtodBody.getUnits()) {
			bodyReversed.add(unit);
		}
		Collections.reverse(bodyReversed);
		
		int startingLineNum = -1;
		
		for (Unit u : bodyReversed) {
			boolean broken = false;
			if (u instanceof JAssignStmt && BroadcastSenderReceiversMapper.isInitializationOf(u, type)) {
				for (ValueBox valueBox : u.getDefBoxes()) {
					if (valueBox.getValue().toString().equals(vb.getValue().toString())) {
						startingLineNum = u.getJavaSourceStartLineNumber();
						broken = true;
						break;
					}
				}
			}
			if (broken)
				break;
		}
		
		for (Unit u : mehtodBody.getUnits()) {
			if (u.getJavaSourceStartLineNumber() < startingLineNum)
				continue;
			for (ValueBox valueBox : u.getUseBoxes()) {
				if (valueBox instanceof InvokeExprBox && (valueBox.toString().contains("void <init>(java.lang.String)") || valueBox.toString().contains("android.content.Intent setAction(java.lang.String)") || valueBox.toString().contains("void addAction(java.lang.String)"))) {
					for (ValueBox _valueBox : valueBox.getValue().getUseBoxes()) {
						if (_valueBox.getValue().toString().contains("\"")) {
							String action = _valueBox.getValue().toString().replaceAll("\"", "");
							return action;
							//System.out.println();
						}
					}
					//UNCOMMENT - System.out.println(valueBox + " -> " + valueBox.getValue().getUseBoxes());
				}
			}
			//System.out.println(u.getJavaSourceStartLineNumber() + " - " + u);
		}
		return null;
	}
	
	private static String[] gerParameters(Unit u) {
		for (UnitBox ub : u.getUnitBoxes()) {
			System.out.println(ub.toString());
		}
		for (ValueBox ub : u.getUseAndDefBoxes()) {
			System.out.println(ub.toString());
		}
		return null;
	}
	
	public static void main(String[] args) throws IOException {
		File dir = new File(DEXES_FOLDER);
		File[] files = dir.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				// @TODO FixMe!
				// Problematic jar/dex files which cause an internal soot exception which I cannot resolve!
				if (Constants.EXCLUDED_JARS.contains(name))
					return false;
				return name.contains("SystemUI.apk.dex");
			}
		});
		
		File fout = new File(OUTPUT + "broadcast-sender-receiver.txt");
		FileOutputStream fos = new FileOutputStream(fout);
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));

		for (File dexFile : files) {
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.myTransform", new SceneTransformer() {
				@Override
				protected void internalTransform(String phaseName, Map options) {
					//final CallGraph cg = Scene.v().getCallGraph();
					
					int count = 0;
					Chain<SootClass> classes = Scene.v().getApplicationClasses();				
					for (SootClass clazz : classes) {
						try {
							for (SootMethod method : clazz.getMethods()) {
								Body body = null;
								try {
									body = method.retrieveActiveBody();
								} catch (Exception e) {
									//e.printStackTrace();
								}
								if (body != null) {
									for (Unit u : body.getUnits()) {
										String permission = null;
										String action = null;
										for (String sendBroadcastMethod : sendBroadcastMethods) {
											if (u.toString().contains(sendBroadcastMethod) && u.getUseBoxes().size() > 3) {
												
												String log1 = "[Method]: " + clazz.getName() + " - " + method.getName()   + " - " + u.toString();
												if (clazz.getName().equals("android.app.ContextImpl") || clazz.getName().equals("android.content.ContextWrapper")) {
													continue;
												}
//												System.out.println(log1);
												
//												bw.append(log1);
//												bw.flush();
												
												String paramType = u.getUseBoxes().get(1).getValue().getType().toString();
												if (u.getUseBoxes().size() == 4 && (paramType.equals("null_type") || paramType.equals("android.os.UserHandle"))) {
//													System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>" + paramType);
													continue;
												}
												
												//sendOrderedBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String,
												//	android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)
												paramType = u.getUseBoxes().get(2).getValue().getType().toString();
												if (u.toString().contains(" sendOrderedBroadcastAsUser(") && u.getUseBoxes().size() == 10 && paramType.equals("null_type")) {
//													System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>" + paramType);
													continue;
												}
												
												//sendBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String)
												paramType = u.getUseBoxes().get(2).getValue().getType().toString();
												if (u.toString().contains(" sendBroadcastAsUser(") && u.getUseBoxes().size() == 5 && paramType.equals("null_type")) {
//													System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>" + paramType);
													continue;
												}
												
												for (ValueBox uu : u.getUseBoxes()) {
													if ((uu instanceof ImmediateBox) && uu.getValue().getType().toString().equals(INTENT_CLASS)) {
														action = BroadcastSenderReceiversMapper.getInitializationStatement(body, uu, INTENT_CLASS);
														//System.out.println("> Action: " + action);
													}
													if ((uu instanceof ImmediateBox) && uu.getValue().getType().toString().equals(STRING_CLASS)) {
														permission = uu.getValue().toString().replaceAll("\"", "");
														//System.out.println("> Permission: " + uu.getValue().toString().replaceAll("\"", "") + "\n\n\n");	
													}
													if ((uu instanceof ImmediateBox) && uu.getValue().getType().toString().equals(STRING_ARRAY_CLASS)) {
														System.out.println();
														bw.append(">>>>>>>>>> : " + clazz.getName() + " - " + method.getName());
														bw.flush();
														bw.append(">>>>>>>>>> : " + uu.getValue().toString());
														bw.flush();
														//Main.getInitializationStatement(body, uu, STRING_ARRAY_CLASS);
													}
												}
											}
										}
										String log = "";
										
										if (permission != null || action != null) {
											
											String methodFormatted = method.getName() + "(" + method.getParameterTypes().stream().map(Object::toString).collect(Collectors.joining(", ")) + ")";
											String ses = "{\"class\": \"" + clazz.getName() + "\", \"method\": \""+methodFormatted+"\", \"permissions\": [\""+permission+"\"], \"actions\": [\""+action+"\"]},";
											if (permission != null && action != null) {
												log = "[2] " + permission + " > " + action;
											} else if(permission != null && action == null) {
												log = "[1] " + permission + " > " + action;
											} else {
												log = "[-] " + permission + " > " + action;
											}
											System.out.println(ses);
											bw.append(ses);
											bw.flush();
										}
										
										String permission2 = null;
										String action2 = null;
										for (String registerBroadcastMethod : registerBroadcastMethods) {
											if (u.toString().contains(registerBroadcastMethod) && u.getUseBoxes().size() > 3) {
												
												if (clazz.getName().equals("android.app.ContextImpl") || clazz.getName().equals("android.content.ContextWrapper") || !u.toString().contains("java.lang.String")) {
													continue;
												}
												
												String paramType = "";
												paramType = u.getUseBoxes().get(2).getValue().getType().toString();
												if (u.toString().contains(" registerReceiver(") && (u.getUseBoxes().size() == 6 || u.getUseBoxes().size() == 7) && paramType.equals("null_type")) {
													continue;
												}
												
												paramType = u.getUseBoxes().get(4).getValue().getType().toString();
												if (u.toString().contains(" registerReceiver(") && u.getUseBoxes().size() == 9 && paramType.equals("null_type")) {
													continue;
												}
												
												paramType = u.getUseBoxes().get(3).getValue().getType().toString();
												if (u.toString().contains(" registerReceiverAsUser(") && u.getUseBoxes().size() == 7 && paramType.equals("null_type")) {
													continue;
												}
												
												paramType = u.getUseBoxes().get(2).getValue().getType().toString();
												if (u.toString().contains(" registerReceiverForAllUsers(") && u.getUseBoxes().size() == 6 && paramType.equals("null_type")) {
													continue;
												}
												
												String log1 = clazz.getName() + " - " + method.getName() + "(" + method.getParameterTypes().stream().map(Object::toString).collect(Collectors.joining(", ")) + ")";
												System.out.println("[Method]: " + log1   + " - " + u.toString());
												
												bw.append(log1);
												bw.flush();
												
												for (ValueBox uu : u.getUseBoxes()) {
													if ((uu instanceof ImmediateBox) && uu.getValue().getType().toString().equals(INTENT_FILTER_CLASS)) {
														action2 = BroadcastSenderReceiversMapper.getInitializationStatement(body, uu, INTENT_FILTER_CLASS);
														//System.out.println("> Action: " + action);
													}
													if ((uu instanceof ImmediateBox) && uu.getValue().getType().toString().equals(STRING_CLASS)) {
														permission2 = uu.getValue().toString().replaceAll("\"", "");
													}
												}
											}
										}
										if (permission2 != null || action2 != null) {
											bw.append(permission2 + ": [" + action2 + "]");
											bw.flush();
											System.out.println(permission2 + " " + action2);
										}
									}
								}
								
							}
						} catch (Exception e) {
							// e.printStackTrace();
						}
					}
					
				}
			}));
			
			System.out.println(dexFile.getAbsolutePath());
			String[] sootOptions = {
					"-w",
			        "-allow-phantom-refs",
			        "-android-jars", ANDROID_JARS,
			        "-v",
			        "-src-prec", "apk",
			        "-f", "jimple",
			        "-process-dir", dexFile.getPath(),
			        "-keep-line-number",
			        "-output-dir", OUTPUT,
			        "-process-multiple-dex",
			        "-ignore-classpath-errors",
			        "-ignore-resolution-errors",
			        "-search-dex-in-archives"
			};

			try {
				soot.Main.main(sootOptions);
				G.reset();
			} catch (Exception e) {
				
			}
		}
		
		bw.close();
	}

}
