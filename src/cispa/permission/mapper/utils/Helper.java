package cispa.permission.mapper.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

public class Helper {

	public static List<String> getJsonArrayAsList(JsonArray jsonArray) {
		List<String> res = new ArrayList<>();
		for (JsonElement je : jsonArray) {
			res.add(je.getAsString());
		}
		return res;
	}

	// Code copied from here: https://stackoverflow.com/a/49454807
	public static void runScript(String serviceMappingPath, String jimpleDir) {
		Process process = null;
		try {
			process = Runtime.getRuntime().exec(new String[] { "./external/parser.py", serviceMappingPath, jimpleDir });
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
		InputStream stdout = process.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(stdout, StandardCharsets.UTF_8));
		String line;
		try {
			while ((line = reader.readLine()) != null) {
				System.out.println("stdout: " + line);
			}
		} catch (IOException e) {
			System.out.println("Exception in reading output" + e.toString());
		}
	}
}
