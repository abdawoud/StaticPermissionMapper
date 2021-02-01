package cispa.permission.mapper.analysis;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import cispa.permission.mapper.utils.Constants;
import cispa.permission.mapper.utils.Helper;
import cispa.permission.mapper.utils.IOHelper;

public class ServiceApisAnalysis {

	public ServiceApisAnalysis() {}
	
	public void execute() {
		try {
			final BufferedWriter serviceMappingWriter = IOHelper.getWriter(Constants.SERVICE_MAPPING_FILE, false);
			HashMap<String, List<String>> serviceMapping = new HashMap<>();
			
			final BufferedReader binderInterfacesReader = IOHelper.getReader(Constants.BINDER_INTERFACES_FILE);

			BufferedReader br = IOHelper.getReader(Constants.GLOBAL_MAPPING_FILE);
			JsonObject mapping = new JsonParser().parse(br).getAsJsonObject();
			Set<String> keys = mapping.keySet();

			String methodSignature = binderInterfacesReader.readLine();
			
			int i = 0;
			while (methodSignature != null) {
				methodSignature = methodSignature.replaceAll("<", "").replaceAll(">", "");
				
				if (keys.contains(methodSignature)) {
					System.out.println((i++) + " >> " + methodSignature + " - " + mapping.getAsJsonArray(methodSignature).toString());
					serviceMapping.put(methodSignature, Helper.getJsonArrayAsList(mapping.getAsJsonArray(methodSignature)));
				} else {
					String methodNameFromKey;
					String methodNameFromSig;
					String matching = null;
					boolean allMatching = true;
					String[] prev = null;
					String[] current = null;
					for (String k : keys) {
						methodNameFromKey = k.split(": ")[1];
						methodNameFromSig = methodSignature.split(": ")[1];
						if (methodNameFromKey.equals(methodNameFromSig)) {
							int idx = 0;
							current = new String[mapping.getAsJsonArray(k).size()];
							for (JsonElement je : mapping.getAsJsonArray(k)) {
								current[idx] = je.getAsString();
								idx++;
							}
							
							if (prev != null && current != null && !Arrays.equals(prev, current)) {
								allMatching = false;
							}
							prev = current;
							
							matching = k;
						}
					}
					if (allMatching && matching != null) {
						if (mapping.getAsJsonArray(matching).size() > 0 && 
								!mapping.getAsJsonArray(matching).toString().contains("android.permission.INTERNET")) {
							System.out.println((i++) + " >> " + methodSignature + " - " + mapping.getAsJsonArray(matching).toString());
							serviceMapping.put(methodSignature, Helper.getJsonArrayAsList(mapping.getAsJsonArray(matching)));
						}
					}
				}
				
				methodSignature = binderInterfacesReader.readLine();
			}
			
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			serviceMappingWriter.write(gson.toJson(serviceMapping));
			serviceMappingWriter.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
