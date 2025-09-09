package laughcandidate.yellowribbonbe.product.entity;

import lombok.Getter;

@Getter
public enum ProductCategory {
    LOAN("대출"),
    DEPOSIT("예금"), 
    SAVINGS("적금"),
    INSURANCE("보험");

    private final String description;

    ProductCategory(String description) {
        this.description = description;
    }
}
