package laughcandidate.yellowribbonbe.product.util;

import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;

@Component
public class ScoreConverter {

    public int convertToScore(ProductCategory category, String indicator, BigDecimal value, BigDecimal compareValue) {
        if (value == null || compareValue == null) {
            return 50; // 기본 점수
        }
        
        return switch (category) {
            case LOAN -> calculateLoanScore(indicator, value, compareValue);
            case DEPOSIT -> calculateDepositScore(indicator, value, compareValue);
            case SAVINGS -> calculateSavingsScore(indicator, value, compareValue);
            case INSURANCE -> calculateInsuranceScore(indicator, value, compareValue);
        };
    }
    
    private int calculateLoanScore(String indicator, BigDecimal value, BigDecimal compareValue) {
        return switch (indicator) {
            case "금리", "중도상환수수료율", "총이자부담액", "월상환액" -> {
                // 낮을수록 좋은 지표들 (역비례)
                yield calculateInverseScore(value, compareValue);
            }
            case "최대한도" -> {
                // 높을수록 좋은 지표 (정비례)  
                yield calculateDirectScore(value, compareValue);
            }
            default -> 50;
        };
    }
    
    private int calculateDepositScore(String indicator, BigDecimal value, BigDecimal compareValue) {
        return switch (indicator) {
            case "금리", "중도해지이율", "만기이자", "우대조건" -> {
                // 높을수록 좋은 지표들 (정비례)
                yield calculateDirectScore(value, compareValue);
            }
            case "최소예치금" -> {
                // 낮을수록 좋은 지표 (역비례)
                yield calculateInverseScore(value, compareValue);
            }
            default -> 50;
        };
    }
    
    private int calculateSavingsScore(String indicator, BigDecimal value, BigDecimal compareValue) {
        return switch (indicator) {
            case "금리", "만기수령액", "최대한도", "중도해지이율", "우대조건" -> {
                // 높을수록 좋은 지표들 (정비례)
                yield calculateDirectScore(value, compareValue);
            }
            default -> 50;
        };
    }
    
    private int calculateInsuranceScore(String indicator, BigDecimal value, BigDecimal compareValue) {
        return switch (indicator) {
            case "보장금액", "우대조건" -> {
                // 높을수록 좋은 지표들 (정비례)
                yield calculateDirectScore(value, compareValue);
            }
            case "보험료" -> {
                // 낮을수록 좋은 지표 (역비례)
                yield calculateInverseScore(value, compareValue);
            }
            default -> 50;
        };
    }
    

    private int calculateDirectScore(BigDecimal value, BigDecimal compareValue) {
        if (value.equals(compareValue)) {
            return 50; // 동점일 때
        }
        
        BigDecimal maxValue = value.max(compareValue);
        if (maxValue.compareTo(BigDecimal.ZERO) == 0) {
            return 50; // 둘 다 0이면 동점
        }
        
        // s(x) = 50 + 50 × (x-y)/max(x,y)
        BigDecimal difference = value.subtract(compareValue);
        BigDecimal ratio = difference.divide(maxValue, 4, RoundingMode.HALF_UP);
        BigDecimal score = BigDecimal.valueOf(50).add(ratio.multiply(BigDecimal.valueOf(50)));
        
        // 0-100 범위 보장
        int result = score.setScale(0, RoundingMode.HALF_UP).intValue();
        return Math.max(0, Math.min(100, result));
    }
    

    private int calculateInverseScore(BigDecimal value, BigDecimal compareValue) {
        if (value.equals(compareValue)) {
            return 50; // 동점일 때
        }
        
        BigDecimal maxValue = value.max(compareValue);
        if (maxValue.compareTo(BigDecimal.ZERO) == 0) {
            return 50; // 둘 다 0이면 동점
        }
        
        // s(x) = 50 + 50 × (y-x)/max(x,y)
        BigDecimal difference = compareValue.subtract(value);
        BigDecimal ratio = difference.divide(maxValue, 4, RoundingMode.HALF_UP);
        BigDecimal score = BigDecimal.valueOf(50).add(ratio.multiply(BigDecimal.valueOf(50)));
        
        // 0-100 범위 보장
        int result = score.setScale(0, RoundingMode.HALF_UP).intValue();
        return Math.max(0, Math.min(100, result));
    }
}
