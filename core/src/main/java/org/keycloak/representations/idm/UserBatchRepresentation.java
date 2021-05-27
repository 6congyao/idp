package org.keycloak.representations.idm;
import java.util.List;

public class UserBatchRepresentation {
    protected List<String> delete;
    protected List<String> reset;

    public List<String> getDelete() {
        return delete;
    }

    public void setDelete(List<String> delete) {
        this.delete = delete;
    }

    public List<String> getReset() {
        return reset;
    }

    public void setReset(List<String> reset) {
        this.reset = reset;
    }
}
