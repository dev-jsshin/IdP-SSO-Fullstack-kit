package com.idpserver.entity.idp;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import org.hibernate.annotations.DynamicUpdate;

@Entity
@Table(name = "TM_IDP_PROVIDER")
@Data
@Builder
@DynamicUpdate
@AllArgsConstructor
public class TmIdPProvider {

    /* IDP GROUP 고유일련번호 */
    @Id
    @Column(name = "IDP_GROUP_SN")
    private Long idpGroupSn;

    /* IDP 로그인 URL */
    @Column(name = "LOGIN_URL", nullable = false)
    private String loginUrl;

    /* 코드 발급 경로 (Authorization Endpoint) */
    @Column(name = "AUTHORIZATION_CODE_URI", nullable = false)
    private String authorizationCodeUri;

    /* 토큰 발급 경로 (Token Endpoint) */
    @Column(name = "TOKEN_URI", nullable = false)
    private String tokenUri;

    /* 사용자 정보 경로 (UserInfo Endpoint) */
    @Column(name = "USER_INFO_URI")
    private String userInfoUri;

    /* 공개키 경로 (JWK Set URI) */
    @Column(name = "JWK_SET_URI")
    private String jwkSetUri;

    /* 사용자 식별 클레임 이름 */
    @Column(name = "USER_NAME_ATTRIBUTE_NM")
    @Builder.Default
    private String userNameAttributeNm = "sub"; // 기본값 "sub" 설정

    // TnIdPGroup(One) -> TmIdPProvider(One)
    @OneToOne(fetch = FetchType.LAZY)
    @MapsId // idpGroupSn 필드 값을 tnIdPGroup 엔티티의 ID 값으로 매핑
    @JoinColumn(name = "IDP_GROUP_SN")
    @ToString.Exclude
    private TnIdPGroup tnIdPGroup;

    public TmIdPProvider() {

    }
}
