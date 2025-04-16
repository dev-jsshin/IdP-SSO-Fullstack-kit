package com.idpserver.global.entity.idp;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.idpserver.global.entity.client.TnClient;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.hibernate.annotations.DynamicUpdate;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Builder
@Entity
@Table(name = "TN_IDP_GROUP")
@Data
@DynamicUpdate
@AllArgsConstructor
public class TnIdPGroup {

    /* IDP GROUP 고유일련번호 */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "IDP_GROUP_SN")
    private Long idpGroupSn;

    /* IDP GROUP 이름 */
    @Column(name = "IDP_GROUP_NM")
    private String idpGroupNm;

    /* IDP GROUP 상태 (1 : 정상 , 2 : 잠금 , 9 : 탈퇴) */
    @Column(name = "IDP_GROUP_STATUS")
    private String idpGroupStatus;

    /* 비고 */
    @Column(name = "REMARKS")
    private String remarks;

    /* 등록자 고유일련번호 */
    @Column(name = "REG_SN")
    private Long regSn;

    /* 등록 일시 */
    @Column(name = "REG_DT", updatable = false)
    @Temporal(TemporalType.TIMESTAMP)
    @JsonFormat(shape= JsonFormat.Shape.STRING, pattern="yyyy-MM-dd HH:mm:ss")
    private Date regDt;

    /* 변경자 고유일련번호 */
    @Column(name = "MOD_SN")
    private Long modSn;

    /* 변경 일시 */
    @Column(name = "MOD_DT")
    @Temporal(TemporalType.TIMESTAMP)
    @JsonFormat(shape= JsonFormat.Shape.STRING, pattern="yyyy-MM-dd HH:mm:ss")
    private Date modDt;

    /* 삭제자 고유일련번호 */
    @Column(name = "DEL_SN")
    private Long delSn;

    /* 삭제 일시 */
    @Column(name = "DEL_DT")
    @Temporal(TemporalType.TIMESTAMP)
    @JsonFormat(shape= JsonFormat.Shape.STRING, pattern="yyyy-MM-dd HH:mm:ss")
    private Date delDt;

    // TnIdPGroup(One) -> TnClient(Many)
    @OneToMany(mappedBy = "tnIdPGroup", fetch = FetchType.LAZY)
    @ToString.Exclude
    @Builder.Default
    private Set<TnClient> TnClients = new HashSet<>();

    // TnIdPGroup(One) -> TmIdPAdditionalFeature(One)
    @OneToOne(mappedBy = "tnIdPGroup", fetch = FetchType.LAZY)
    @ToString.Exclude
    @Builder.Default
    private TmIdPAdditionalFeature tmIdPAdditionalFeature = new TmIdPAdditionalFeature();

    // TnIdPGroup(One) -> TmIdPProvider(One)
    @OneToOne(mappedBy = "tnIdPGroup", fetch = FetchType.LAZY)
    @ToString.Exclude
    @Builder.Default
    private TmIdPProvider tmIdPProvider = new TmIdPProvider();

    public TnIdPGroup() {}
}
