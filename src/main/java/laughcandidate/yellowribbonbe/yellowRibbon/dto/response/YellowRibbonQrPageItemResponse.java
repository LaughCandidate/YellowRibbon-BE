package laughcandidate.yellowribbonbe.yellowRibbon.dto.response;

public record YellowRibbonQrPageItemResponse(
        Long badgeId,
        String category,
        String description,
        String successDescription,
        String imageUrl
) {
}
