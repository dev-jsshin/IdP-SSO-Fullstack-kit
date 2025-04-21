package com.idpserver.entity.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.hibernate.annotations.DynamicUpdate;

import java.util.Date;

@Entity
@Table(name = "TN_USER")
@Data
@Builder
@DynamicUpdate
@AllArgsConstructor
public class TnUser {

    /* 사용자 고유일련번호 */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "USER_SN")
    private Long userSn;

    /* IdP GROUP 고유일련번호 */
    @Column(name = "IDP_GROUP_SN", nullable = false)
    private Long idpGroupSn;

    /* 사용자 ID */
    @Column(name = "USER_ID", nullable = false)
    private String userId;

    /* 사용자 이름 */
    @Column(name = "USER_NM")
    private String userNm;

    /* 사용자 비밀번호 */
    @Column(name = "PASSWORD", nullable = false)
    private String password;

    /* 휴대폰 번호 */
    @Column(name = "MOBILE")
    private String mobile;

    /* 이메일 */
    @Column(name = "EMAIL")
    private String email;

    /* 이메일 인증여부 (Y : 인증 , N : 미인증) */
    @Column(name = "EMAIL_AUTH_YN")
    private String emailAuthYn;

    /* 사용자 유형 (1 : AD , 2 : 일반사용자) */
    @Column(name = "USER_TYPE", nullable = false)
    private String userType;

    /* 사용자 상태 (1 : 정상 , 2 : 잠금 , 9 : 탈퇴) */
    @Column(name = "USER_STATUS")
    private String userStatus;

    /* 로그인 실패 횟수 */
    @Column(name = "LOGIN_FAILURE_CNT")
    private Integer loginFailureCnt;

    /* 패스워드 수정일시 */
    @Column(name = "PASSWORD_MOD_DT")
    @JsonFormat(shape= JsonFormat.Shape.STRING, pattern="yyyy-MM-dd HH:mm:ss")
    private Date passwordModDt;

    /* 최근 로그인 일시 */
    @Column(name = "LOGIN_LAST_DT")
    @JsonFormat(shape= JsonFormat.Shape.STRING, pattern="yyyy-MM-dd HH:mm:ss")
    private Date loginLastDt;

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

    public TnUser() {}
}
