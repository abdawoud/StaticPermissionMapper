package cispa.permission.mapper.models;

import java.util.ArrayList;
import java.util.List;

import soot.SootMethod;

public class SinkMethod {
	private SootMethod method;
	private List<String> permissions;
	
	public SinkMethod() {
		this.method = null;
		this.permissions = new ArrayList<String>();
	}
	
	public SinkMethod(SootMethod method) {
		this.setMethod(method);
		this.permissions = new ArrayList<String>();
	}
	
	public SinkMethod(SootMethod method, List<String> permissions) {
		this.setMethod(method);
		this.setPermissions(permissions);
	}

	public SootMethod getMethod() {
		return method;
	}

	public void setMethod(SootMethod method) {
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
