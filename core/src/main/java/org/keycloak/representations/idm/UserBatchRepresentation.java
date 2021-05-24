package org.keycloak.representations.idm;
import java.util.List;

public class UserBatchRepresentation {
    protected List<String> delete;

    public List<String> getDelete() {
        return delete;
    }

    public void setDelete(List<String> delete) {
        this.delete = delete;
    }
}
