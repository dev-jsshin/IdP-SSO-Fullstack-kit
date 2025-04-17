package com.idpserver.global.entity.client;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.idpserver.global.entity.idp.TnIdPGroup;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicUpdate;

import java.util.Date;

@Entity
@Table(name = "TN_CLIENT")
@Data
@Builder
@DynamicUpdate
@AllArgsConstructor
public class TnClient {

    /* 클라이언트 고유일련번호 */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "CLIENT_SN")
    private Long clientSn;

    // --- 관계 Mapping (TnIdPGroup 과의 다대일 관계) ---
    // TnClient(Many) -> TnIdPGroup(One)
    // fetch = FetchType.EAGER: 기본값. 클라이언트 로드 시 그룹 정보도 즉시 로드 (LAZY 권장)
    @ManyToOne(fetch = FetchType.LAZY) // LAZY 로딩 권장
    @JoinColumn(name = "IDP_GROUP_SN", nullable = false) // DB의 외래키 컬럼 이름 지정 및 Not Null 제약
    @ToString.Exclude // 순환 참조 방지
    private TnIdPGroup tnIdPGroup;

    /* 클라이언트 ID */
    @Column(name = "CLIENT_ID", nullable = false)
    private String clientId;

    /* 클라이언트 시크릿 */
    @Column(name = "CLIENT_SECRET", nullable = false)
    private String clientSecret;

    /* 클라이언트 시크릿 해시 */
    @Column(name = "CLIENT_SECRET_HASH", nullable = false)
    private String clientSecretHash;

    /* 클라이언트 이름 */
    @Column(name = "CLIENT_NM", nullable = false)
    private String clientNm;

    /* 클라이언트 상태 */
    @Column(name = "CLIENT_STATUS", nullable = false)
    private String clientStatus;

    /* 비고 */
    @Column(name = "REMARKS")
    private String remarks;

    // TnClient(One) -> TmClientSetting(One)
    @OneToOne(mappedBy = "tnClient", fetch = FetchType.LAZY)
    @ToString.Exclude
    private TmClientSetting tmClientSetting;

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

    public TnClient() {}
}
