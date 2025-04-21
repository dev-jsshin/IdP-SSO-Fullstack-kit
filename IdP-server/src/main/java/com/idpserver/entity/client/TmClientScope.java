package com.idpserver.entity.client;

import com.idpserver.entity.client.pkGroup.TmClientScopeId;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.hibernate.annotations.DynamicUpdate;

@Entity
@Table(name = "TM_CLIENT_SCOPE")
@IdClass(TmClientScopeId.class)
@Data
@Builder
@DynamicUpdate
@AllArgsConstructor
public class TmClientScope {

    /* CLIENT 고유일련번호 */
    @Id
    @Column(name = "CLIENT_SN")
    private Long clientSn;

    /* SCOPE 고유일련번호 */
    @Id
    @Column(name = "SCOPE_SN")
    private Long scopeSn;

    // TmClientScope(Many) -> TnClient(One)
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "CLIENT_SN", referencedColumnName = "CLIENT_SN", insertable = false, updatable = false)
    @ToString.Exclude
    private TnClient tnClient;

    // TmClientScope(Many) -> TnScope(One)
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "SCOPE_SN", referencedColumnName = "SCOPE_SN", insertable = false, updatable = false)
    @ToString.Exclude
    private TnScope tnScope;

    public TmClientScope() {}
}
