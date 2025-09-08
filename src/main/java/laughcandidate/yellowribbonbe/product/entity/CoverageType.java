package laughcandidate.yellowribbonbe.product.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CoverageType {

    FIRE("사업장 화재 보험"),
    NATURAL_DISASTER("풍수해/자연재해 보험"),
    LIABILITY("영업 배상책임 보험"),
    BUSINESS_INTERRUPTION("휴업손해 보상 보험"),
    PROPERTY_DAMAGE("시설/재물손괴 보험");

    private final String description;
}