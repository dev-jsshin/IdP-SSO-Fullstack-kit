package com.idpserver.entity.client.pkGroup;

import lombok.*;
import java.io.Serializable;
import java.util.Objects;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TmClientScopeId implements Serializable {

    private static final long serialVersionUID = 1L;

    private Long clientSn;
    private Long scopeSn;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TmClientScopeId that = (TmClientScopeId) o;
        return Objects.equals(clientSn, that.clientSn) &&
                Objects.equals(scopeSn, that.scopeSn);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientSn, scopeSn);
    }
}