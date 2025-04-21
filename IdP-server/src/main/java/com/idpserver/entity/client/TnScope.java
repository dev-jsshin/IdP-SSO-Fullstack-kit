package com.idpserver.entity.client;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicUpdate;

import java.util.Date;

@Entity
@Table(name = "TN_SCOPE")
@Data
@Builder
@DynamicUpdate
@AllArgsConstructor
public class TnScope {

    /* SCOPE 고유일련번호 */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "SCOPE_SN")
    private Long scopeSn;

    /* SCOPE 이름 (예: "openid", "profile") */
    @Column(name = "SCOPE_NM", nullable = false)
    private String scopeNm;

    /* 지정 유형 (1: Default, 2: Optional) */
    @Column(name = "ASSIGNED_TYPE")
    @Builder.Default
    private String assignedType = "2";

    /* SCOPE 설명 */
    @Column(name = "DESCRIPTION")
    private String description;

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


    public TnScope() {

    }
}
