package laughcandidate.yellowribbonbe.product.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.product.dto.*;
import jakarta.validation.Valid;
import laughcandidate.yellowribbonbe.product.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "금융상품")
@RestController
@RequestMapping("/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    @GetMapping
    @Operation(
        summary = "금융상품 리스트 조회 API",
        description = "혜택 금융상품 리스트를 조회합니다.")
    public ResponseEntity<ApiResponse<List<ProductListResponse>>> getProducts(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Long badgeId,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        List<ProductListResponse> products = productService.getProducts(category, badgeId);
        return ResponseEntity.ok(ApiResponse.ok(products));
    }

    @GetMapping("/{productId}")
    @Operation(
        summary = "금융상품 상세 조회 API",
        description = "특정 금융상품의 상세 정보를 조회합니다.")
    public ResponseEntity<ApiResponse<ProductDetailResponse>> getProductDetail(
            @PathVariable Long productId,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        ProductDetailResponse productDetail = productService.getProductDetail(productId);
        return ResponseEntity.ok(ApiResponse.ok(productDetail));
    }

    @GetMapping("/my-benefits")
    @Operation(
        summary = "나의 보유 혜택 상품 조회 API",
        description = "현재 로그인한 사용자가 보유한 혜택 상품 목록을 조회합니다.")
    public ResponseEntity<ApiResponse<List<UserBenefitProductResponse>>> getMyBenefitProducts(
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        List<UserBenefitProductResponse> myBenefitProducts = 
                productService.getMyBenefitProducts(customUserDetails.getUserId());
        return ResponseEntity.ok(ApiResponse.ok(myBenefitProducts));
    }

    @PostMapping("/{productId}/compare")
    @Operation(
        summary = "금융상품 비교 API",
        description = "혜택 금융상품과 사용자 보유 상품을 비교합니다.")
    public ResponseEntity<ApiResponse<ComparisonResponse>> compareProducts(
            @PathVariable Long productId,
            @RequestBody @Valid CompareRequest request,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        ComparisonResponse comparison = productService.compareProducts(
                productId, request.getMyDataId(), customUserDetails.getUserId());
        return ResponseEntity.ok(ApiResponse.ok(comparison));
    }
}
