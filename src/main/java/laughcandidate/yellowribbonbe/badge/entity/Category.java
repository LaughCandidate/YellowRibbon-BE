package laughcandidate.yellowribbonbe.badge.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Category {

    SOCIAL_INCLUSION("사회적 포용"),
    SAFETY_ENHANCEMENT("안전 강화"),
    LOCAL_COEXISTENCE("지역 상생"),
    ENVIRONMENT_PROTECTION("환경 보호"),
    TRANSPARENT_MANAGEMENT("투명 경영");

    private final String category;
}
