package cispa.permission.mapper.utils;

import java.util.ArrayList;
import java.util.List;

import cispa.permission.mapper.models.ParsedMethod;
import cispa.permission.mapper.models.SinkMethod;

public class StringParser {

	public static String[] getParametersFromMethodInvocation(String statement) {
		try {
			return statement.replace(" ", "").split(">\\(")[1].split("\\)")[0].split(",");
		} catch (Exception e) {
			return new String[0];
		}
	}

	public static String[] parseMethodFromInvocationStatment(String statement) {
		String sink = (statement.contains("<"))? statement.split("<")[1].split(">")[0] : null;
		if (sink == null) {
			return null;
		}
		
		String sinkClass = sink.split(": ")[0].trim();
		String sinkMethod = sink.split(": ")[1].trim();
		
		return new String[] {sink, sinkClass, sinkMethod};
	}
	
	public static String asMethodSignature(String sinkClass, String sinkMethod) {
		return "<" + sinkClass + ": " + sinkMethod + ">";
	}
	
	public static boolean hasPermissionSomewhere(String statement) {
		boolean containsPermission = false;
		for (String s : getStrings(statement)) {
			if (s.contains(".permission.")) {
				containsPermission = true;
				break;
			}
		}
		return containsPermission;
	}
	
	public static String[] getStrings(String targetString) {
		String[] tokens = targetString.split("\"");
		List<String> strings = new ArrayList<String>();
		for (int i = 1; i < tokens.length; i += 2) {
		    strings.add(tokens[i]);
		}
		String[] result = strings.toArray(new String[0]);
		return result;
	}
	
	public static ParsedMethod getMethodAndPermissions(String statement) {
		ParsedMethod parsedMethod = new ParsedMethod();
		String[] parameters = getParametersFromMethodInvocation(statement);

		if (parameters.length == 0) {
			parsedMethod.setMethod("");
		} else {
			parsedMethod.setMethod(parseMethodFromInvocationStatment(statement)[0]);
		}
		for (String param : parameters) {
			if (param.contains(".permission.")) {
				parsedMethod.setPermission(param.replaceAll("\"", ""));
			}
		}
		return parsedMethod;	
	}
}
