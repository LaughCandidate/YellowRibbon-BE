package laughcandidate.yellowribbonbe.product.entity;

public enum ProductCategory {
    LOAN("대출"),
    DEPOSIT("예금"), 
    SAVINGS("적금"),
    INSURANCE("보험");

    private final String description;

    ProductCategory(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
