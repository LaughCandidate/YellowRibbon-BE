package laughcandidate.yellowribbonbe.product.controller;

import laughcandidate.yellowribbonbe.product.dto.ProductListResponse;
import laughcandidate.yellowribbonbe.product.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "금융상품")
@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;


    @GetMapping
    @Operation(
        summary = "혜택 금융상품 리스트 조회 API",
        description = "금융상품 리스트를 조회합니다.\n" +
                "            \n" +
                "            **카테고리별 조회 가능:**\n" +
                "            - `LOAN`: 대출 상품\n" +
                "            - `DEPOSIT`: 예금 상품  \n" +
                "            - `SAVINGS`: 적금 상품\n" +
                "            - `INSURANCE`: 보험 상품\n" +
                "            \n" +
                "            **카테고리 파라미터가 없으면 전체 상품을 조회합니다.**")
    public ResponseEntity<List<ProductListResponse>> getProducts(
            @RequestParam(required = false) String category) {
        
        List<ProductListResponse> products = productService.getProducts(category);
        return ResponseEntity.ok(products);
    }
}
