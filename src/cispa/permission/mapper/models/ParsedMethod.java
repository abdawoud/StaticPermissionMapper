package cispa.permission.mapper.models;

import java.util.ArrayList;
import java.util.List;


public class ParsedMethod {
	private String method;
	private List<String> permissions;
	
	public ParsedMethod() {
		this.method = null;
		this.permissions = new ArrayList<String>();
	}
	
	public ParsedMethod(String method) {
		this.setMethod(method);
		this.permissions = new ArrayList<String>();
	}
	
	public ParsedMethod(String method, List<String> permissions) {
		this.setMethod(method);
		this.setPermissions(permissions);
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public List<String> getPermissions() {
		return permissions;
	}

	public void setPermissions(List<String> permissions) {
		this.permissions = permissions;
	}
	
	public void setPermission(String permission) {
		this.permissions.add(permission);
	}

}
