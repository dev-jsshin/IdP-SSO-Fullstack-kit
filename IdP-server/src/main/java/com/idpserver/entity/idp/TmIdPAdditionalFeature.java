package com.idpserver.entity.idp;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.hibernate.annotations.DynamicUpdate;

@Entity
@Table(name = "TM_IDP_ADDITIONAL_FEATURE")
@Data
@Builder
@DynamicUpdate
@AllArgsConstructor
public class TmIdPAdditionalFeature {

    /* IDP GROUP 고유일련번호 */
    @Id
    @Column(name = "IDP_GROUP_SN")
    private Long idpGroupSn;

    /* 로그인 실패 허용 횟수 */
    @Column(name = "LOGIN_FAILURE_CNT")
    @Builder.Default
    private Integer loginFailureCnt = 5;

    /* 로그인 제한 시간 (단위: 분) */
    @Column(name = "LOGIN_LOCK_TIMED")
    @Builder.Default
    private String loginLockTimed = "10";

    /* 회원가입 허용 여부 (Y/N) */
    @Column(name = "REGISTRATION_ALLOWED")
    @Builder.Default
    private String registrationAllowed = "N";

    /* 패스워드 초기화 허용 여부 (Y/N) */
    @Column(name = "RESET_PASSWORD_ALLOWED")
    @Builder.Default
    private String resetPasswordAllowed = "N";

    /* 아이디 기억하기 허용 여부 (Y/N) */
    @Column(name = "REMEMBER_USER_ID_ALLOWED")
    @Builder.Default
    private String rememberUserIdAllowed = "N";

    // TnIdPGroup(One) -> TmIdPAdditionalFeature(One)
    @OneToOne(fetch = FetchType.LAZY)
    @MapsId // idpGroupSn 필드 값을 tnSsoGroup 엔티티의 ID 값으로 매핑
    @JoinColumn(name = "IDP_GROUP_SN")
    @ToString.Exclude
    private TnIdPGroup tnIdPGroup;

    public TmIdPAdditionalFeature() {

    }
}
