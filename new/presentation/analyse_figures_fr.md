# Analyse Des Figures - Présentation 10 Slides

Ce fichier explique comment interpréter les figures de la présentation. Il sert surtout à éviter les erreurs pendant la soutenance, notamment sur la comparaison entre SHAP et SmoothIG.

## Point Très Important: SHAP Et SmoothIG N'ont Pas La Même Échelle

Il ne faut pas comparer directement la hauteur brute des barres SHAP avec la hauteur brute des barres SmoothIG. Ce sont deux méthodes différentes, appliquées à des modèles différents, avec des unités différentes.

Les valeurs TreeSHAP mesurent des contributions moyennes dans un modèle à arbres. Une moyenne SHAP inférieure à 0.025 peut être importante si elle est grande par rapport aux autres variables du même graphique.

Les valeurs SmoothIG viennent des Integrated Gradients lissés pour un réseau neuronal. Elles peuvent atteindre 5 ou 6 parce qu'elles représentent des magnitudes de gradients intégrés. Cela ne signifie pas qu'elles sont "plus fortes" que les valeurs SHAP.

La bonne façon d'analyser est donc de comparer le classement des variables à l'intérieur d'une même méthode, le sens sécurité des variables, et les métriques de stabilité. On ne compare pas les valeurs numériques brutes entre SHAP et SmoothIG.

## Slide 4 - Explication Du Modèle Final

Figure: `adv_tree_ensemble_top10.png`

Cette figure montre les variables les plus importantes pour l'ensemble final Adv+ExtraTrees. Les variables dominantes concernent l'état de connexion, le taux de connexions vers le même service, le nombre de connexions côté hôte, l'état de login et les taux d'erreurs.

L'analyse à donner est que ces variables sont cohérentes avec une décision IDS. Une attaque réseau peut produire des changements dans les connexions réussies, dans la répétition d'un service, dans les erreurs ou dans le comportement d'authentification. Le modèle final semble donc utiliser des indices réseau logiques.

Phrase utile: "Cette figure montre que le modèle ne se base pas sur des variables arbitraires; il utilise des signaux réseau cohérents avec la détection d'intrusion."

## Slide 5 - RF SHAP Et SmoothIG

Figures: `rf_shap_top10.png` et `torch_binary_smoothig_top10.png`

La figure RF SHAP explique les décisions du Random Forest avec TreeSHAP. Elle montre quelles variables contribuent le plus aux décisions du modèle arbre.

La figure SmoothIG explique le modèle Torch Binary MLP. Elle repose sur les gradients intégrés et ajoute un lissage pour réduire le bruit des gradients.

Le point important est que les deux figures ne doivent pas être comparées en valeur brute. Si SmoothIG affiche des valeurs beaucoup plus grandes, cela vient de l'échelle de la méthode. Ce qui compte, c'est que les variables importantes restent liées à des comportements réseau: erreurs, services, trafic, protocole et état de connexion.

Phrase utile: "Nous utilisons plusieurs méthodes parce que les familles de modèles sont différentes: TreeSHAP pour les arbres, SmoothIG pour le réseau neuronal."

## Slide 5 - Stabilité Des Explications

Les valeurs de stabilité résument la fiabilité des explications. La stabilité locale Jaccard mesure si les mêmes variables restent importantes autour d'observations proches. Une valeur proche de 1 signifie que les top features restent très similaires.

Les résultats sont élevés: RF SHAP 0.880, Torch IG 0.881, SmoothIG 0.899 et ensemble final 0.845. Cela permet de défendre que les explications sont relativement stables.

La conclusion doit rester nuancée. Une explication stable est utile pour un analyste, mais elle peut aussi aider un attaquant car elle révèle régulièrement les mêmes variables sensibles.

## Slide 6 - Attaques Guidées Par Les Explications

Figures: `rf_shap_evasion_local.png`, `ig_evasion_heatmap.png`, `adv_tree_shap_evasion.png`

La première figure montre qu'une attaque guidée par SHAP peut atteindre 18.22% d'évasion contre Random Forest. La deuxième montre qu'une attaque guidée par Integrated Gradients peut atteindre 15.97% d'évasion contre le Torch MLP.

Ces résultats montrent le caractère dual de l'explicabilité. Les explications aident l'analyste à comprendre l'alerte, mais elles donnent aussi à l'attaquant une indication des variables à modifier.

La troisième figure montre que l'ensemble final résiste mieux: l'évasion guidée par TreeSHAP reste à 0.00% dans les paramètres testés. Il faut dire "dans les paramètres testés", car ce n'est pas une preuve de robustesse universelle.

## Slide 7 - Attaques PGD

Figures: `torch_binary_pgd_evasion.png` et `torch_binary_adv_constrained_pgd_evasion.png`

La première figure montre le PGD full-feature contre le modèle Torch Binary MLP. C'est une attaque white-box très forte, car elle utilise les gradients du modèle et peut modifier toutes les variables normalisées. Elle atteint 100% d'évasion, ce qui montre que le modèle neuronal seul est fragile.

La deuxième figure montre mutable-feature PGD après entraînement adversarial. Cette version est plus réaliste parce que les variables catégorielles et binaires sont gelées. Les améliorations les plus claires apparaissent à eps 0.10 et eps 0.15.

Phrase utile: "Le PGD complet est un stress test, tandis que mutable-feature PGD est plus défendable comme scénario tabulaire réaliste."

## Slide 8 - Défense Transfer-PGD

Figure: `adv_tree_transfer_pgd_defense.png`

Cette figure est la plus importante pour la défense du projet. Les exemples adversariaux sont générés contre le modèle Torch, puis testés contre l'ensemble final.

Le modèle Torch est vulnérable: 37.29%, 63.99%, 91.24% et 100.00% d'évasion selon eps. Mais l'ensemble final réduit ces valeurs à 0.50%, 0.00%, 0.00% et 0.00%. Cela signifie que les attaques qui trompent le modèle neuronal se transfèrent très mal vers l'ensemble robuste.

Phrase utile: "L'ensemble final casse la transférabilité, car il combine une composante neuronale et une composante arbre robuste dont la frontière de décision est différente."

## Slide 9 - Security-OR

Security-OR est un mode plus strict. Il signale une attaque si l'une des composantes est confiante. Il bloque les attaques transfer-PGD testées, mais son F1 propre est plus faible que celui du modèle final Adv+ExtraTrees.

Il ne faut donc pas le présenter comme le modèle principal. Il faut le présenter comme un mode opérationnel optionnel pour les environnements où les faux négatifs sont beaucoup plus coûteux que les alertes supplémentaires.

## Conclusion D'analyse

Les figures racontent une histoire cohérente. Le modèle final utilise des variables réseau logiques, les explications sont relativement stables, les explications peuvent guider des attaques, et l'ensemble final réduit fortement la transférabilité des attaques testées. Les résultats sont solides, mais ils doivent être présentés comme empiriques et limités aux attaques et au dataset testés.
