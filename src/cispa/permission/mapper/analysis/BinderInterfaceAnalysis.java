package cispa.permission.mapper.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.lang.Exception;
import java.util.Map;

import cispa.permission.mapper.utils.AnalysisHelper;
import cispa.permission.mapper.utils.Constants;
import cispa.permission.mapper.utils.IOHelper;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.util.Chain;

public class BinderInterfaceAnalysis {

	public BinderInterfaceAnalysis() {}
	
	public void execute() throws IOException {
		File[] files = IOHelper.getDexFilePaths(new String[] {}, new String[] {});

		String[] sootOptions = {
			"-process-dir", "",
			"-w",
			"-android-jars", Constants.ANDROID_JARS, 
			"-v", 
			"-src-prec", "apk",
			"-f", "jimple",
			"-keep-line-number",
			"-output-dir", Constants.OUTPUT, 
			"-process-multiple-dex", 
			"-search-dex-in-archives",
			"-allow-phantom-refs",
			"-ignore-classpath-errors", 
			"-ignore-resolution-errors",
			"-ignore-resolving-levels"
		};
		
		final BufferedWriter binderInterfacesWriter = IOHelper.getWriter(Constants.BINDER_INTERFACES_FILE, false);
		final ArrayList<String> uniqueBinderInterfaces = new ArrayList<>(); 
		
		for (File dexFile : files) {
			System.out.println(dexFile.getAbsolutePath() + " " + dexFile.getName());
			
			sootOptions[1] = dexFile.getAbsolutePath();
			
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.ManagerServiceMapper", new SceneTransformer() {

				@Override
				protected void internalTransform(String phaseName, Map options) {
					Chain<SootClass> classes = Scene.v().getApplicationClasses();
					System.out.println(classes.size());
					for (SootClass clazz : classes) {
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
								
								if (method.getActiveBody().toString().contains("android.os.IBinder: boolean transact(int,android.os.Parcel,android.os.Parcel,int)")) {
									if (!uniqueBinderInterfaces.contains(method.toString())) {
										System.out.println(method.toString());
										uniqueBinderInterfaces.add(method.toString());
										binderInterfacesWriter.append(method.toString() + "\n");
										binderInterfacesWriter.flush();
									}
								}
							}
						} catch (Exception e) {
							e.printStackTrace();
						}
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
		
		binderInterfacesWriter.close();
	}
}
