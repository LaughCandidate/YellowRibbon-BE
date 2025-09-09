package laughcandidate.yellowribbonbe.yellowRibbon.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "YELLOW_RIBBON")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class YellowRibbon extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "yellow_ribbon_id")
    private Long id;

    @Column(name = "season")
    private Integer season;

}
