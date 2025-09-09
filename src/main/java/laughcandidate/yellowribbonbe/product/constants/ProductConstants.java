package laughcandidate.yellowribbonbe.product.constants;

import java.math.BigDecimal;

public final class ProductConstants {
    
    // 금리 수치 조정
    public static final BigDecimal LOAN_ADDITIONAL_RATE = new BigDecimal("2.31");
    public static final BigDecimal DEPOSIT_ADDITIONAL_RATE = new BigDecimal("1.20");
    public static final BigDecimal SAVINGS_ADDITIONAL_RATE = new BigDecimal("3.00");
    
    // 단위 변환
    public static final long WON_TO_MILLION = 10000L;           // 만원 변환
    public static final long WON_TO_HUNDRED_MILLION = 100000000L; // 억원 변환
    
    // 기타 상수
    public static final String DEFAULT_PERIOD = "12개월 기준";
    public static final String INSURANCE_COVERAGE_PERIOD = "1년 (자동 갱신)";
    
    private ProductConstants() {
    }
}