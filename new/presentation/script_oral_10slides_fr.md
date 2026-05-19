# Script Oral En Français - Présentation 10 Slides

Ce script correspond au fichier `project5_presentation_10slides.html` et au PDF portable `project5_presentation_10slides_portable.pdf`. Il est prévu pour une soutenance courte, environ 10 à 12 minutes. L'idée principale est de présenter le projet comme un IDS explicable et testé face à des attaques adversariales, et non comme une simple comparaison de modèles.

## Slide 1 - Explainable IDS Under Adversarial Pressure

Bonjour. Nous sommes TAMIS Mohammed et GRYACH Ikram, et notre projet porte sur la détection d'intrusions explicable sous pression adversariale. Nous avons travaillé sur le dataset NSL-KDD, qui est le dataset demandé pour le projet, et le modèle final retenu est un ensemble Adv+ExtraTrees.

Le modèle final obtient un F1 binaire de 0.9063 et un PR-AUC de 0.9626. Ces résultats sont importants, mais l'objectif du projet ne se limite pas à obtenir un bon score de classification. Nous avons aussi expliqué les décisions du modèle, mesuré la stabilité des explications, utilisé ces explications pour guider des attaques, puis évalué des mécanismes de défense.

Le résultat de défense le plus important est la réduction de l'évasion en transfert PGD. Les exemples adversariaux générés contre le modèle Torch ne se transfèrent presque pas vers l'ensemble final: l'évasion devient 0.50% à eps 0.03, puis 0.00% à eps 0.06, 0.10 et 0.15. Il faut bien préciser que cela ne prouve pas une robustesse absolue. Cela signifie une robustesse empirique dans le cadre des attaques testées.

## Slide 2 - From Dataset To Defensible IDS Decision

Cette slide présente la logique globale du pipeline. Le dataset contient 125,973 enregistrements dans KDDTrain+ et 22,544 enregistrements dans KDDTest+. Après le prétraitement, nous obtenons 478 variables. Le prétraitement inclut l'encodage one-hot des variables catégorielles, la normalisation des variables numériques et la création de variables dérivées liées au trafic.

Le pipeline suit les exigences du sujet. Nous entraînons plusieurs modèles, notamment Logistic Regression, Random Forest, ExtraTrees, XGBoost et des réseaux MLP avec Torch. Ensuite, nous expliquons les décisions avec TreeSHAP, Integrated Gradients et SmoothIG. Nous mesurons aussi la stabilité des explications, puis nous testons des attaques comme SHAP-guided evasion, IG-guided evasion, PGD et mutable-feature PGD.

La partie défense combine l'entraînement adversarial, les ExtraTrees robustes augmentés avec des exemples guidés par SHAP, et un ensemble hétérogène. Cette organisation permet de répondre aux livrables: performance IDS, explicabilité, stabilité, analyse de sécurité, reproductibilité et limites.

## Slide 3 - Best Default Model: Adv+ExtraTrees Ensemble

Cette slide montre pourquoi nous avons choisi Adv+ExtraTrees comme modèle final par défaut. Il obtient un F1 binaire de 0.9063, un PR-AUC de 0.9626 et une balanced accuracy de 0.9064. Il dépasse les modèles de base et améliore aussi le modèle SHAP-Robust ExtraTrees seul.

La partie droite de la slide montre le rappel par famille d'attaque. DoS et Probe sont très bien détectés, avec des rappels de 0.9859 et 1.0000. Les familles R2L et U2R sont plus difficiles car elles sont plus rares et souvent plus proches du trafic normal. Malgré cela, le modèle final obtient un rappel de 0.6786 pour R2L et de 0.8060 pour U2R.

La conclusion est que le modèle final n'a pas été choisi seulement parce qu'il donne un bon score global. Il est choisi parce qu'il offre le meilleur compromis opérationnel: bonnes métriques propres, meilleure détection des familles rares et bonne résistance aux attaques testées.

## Slide 4 - Explanations Show Meaningful Network Evidence

Cette slide explique la décision du modèle final. Les variables les plus importantes sont liées à l'état de connexion, à la concentration des services, au nombre de connexions vers l'hôte, à l'état de login et aux taux d'erreurs. Ces variables ont du sens pour un IDS, car les attaques modifient souvent les comportements de connexion, les répétitions de services et les erreurs réseau.

Il faut faire attention à l'échelle des valeurs. Les valeurs SHAP et SmoothIG ne sont pas directement comparables. Une valeur SHAP autour de 0.02 ou 0.05 peut être très importante dans l'échelle d'un modèle arbre. En revanche, SmoothIG peut donner des valeurs autour de 5 ou 6, car il s'agit d'attributions basées sur des gradients intégrés dans un réseau de neurones.

Donc, il ne faut pas dire que SmoothIG est plus important que SHAP parce que ses valeurs numériques sont plus grandes. On compare surtout le classement des variables à l'intérieur de chaque méthode, le sens sécurité des variables et la stabilité des explications.

## Slide 5 - Different Explainers, Same Security Story

Cette slide montre pourquoi nous utilisons plusieurs méthodes d'explicabilité. TreeSHAP est adapté aux modèles à arbres, car il mesure la contribution moyenne des variables dans les décisions des arbres. SmoothIG est adapté au modèle neuronal binaire, car il lisse les Integrated Gradients et réduit le bruit local des gradients.

Les métriques de stabilité montrent que les explications sont relativement fiables. RF SHAP obtient une stabilité locale Jaccard de 0.880, Torch IG de 0.881, SmoothIG de 0.899 et l'ensemble final de 0.845. Cela signifie que les variables les plus importantes restent généralement similaires lorsqu'on perturbe légèrement les observations ou lorsqu'on rééchantillonne les données.

La déduction est double. D'un côté, des explications stables aident l'analyste à faire confiance aux alertes. De l'autre côté, elles peuvent aider un attaquant, car elles révèlent de façon régulière quelles variables sont importantes pour contourner le modèle.

## Slide 6 - Explanations Help Analysts, But Also Guide Evasion

Cette slide présente le problème dual de l'explicabilité. Les explications servent à comprendre les décisions, mais elles peuvent aussi guider une attaque. Sur Random Forest, l'attaque guidée par SHAP atteint jusqu'à 18.22% d'évasion. Sur le MLP Torch, l'attaque guidée par Integrated Gradients atteint jusqu'à 15.97%.

Cela montre que les explications ne sont pas seulement descriptives. Elles peuvent indiquer quelles variables influencent suffisamment la décision pour permettre une évasion. En cybersécurité, c'est un point essentiel: une information utile pour l'analyste peut aussi être utile pour l'attaquant.

Le modèle final résiste mieux dans ce cadre. L'évasion guidée par TreeSHAP contre l'ensemble final reste à 0.00% dans les paramètres testés. Cela soutient l'effet de durcissement apporté par les ExtraTrees robustes et par l'ensemble.

## Slide 7 - Neural IDS Alone Remains Vulnerable

Cette slide explique les résultats PGD. Le PGD full-feature est une attaque white-box contre le modèle Torch Binary MLP. Elle est très forte car elle utilise les gradients du modèle et peut modifier toutes les variables normalisées. Sur le modèle Torch original, cette attaque atteint 100% d'évasion.

Mais cette attaque n'est pas totalement réaliste, car elle peut modifier des variables catégorielles ou binaires dans l'espace des features. Pour cette raison, nous avons aussi testé mutable-feature PGD, où les variables catégorielles et binaires sont gelées, et seules les variables continues liées au comportement réseau peuvent être modifiées.

L'entraînement adversarial améliore surtout la robustesse pour les budgets moyens et élevés. La réduction est de 32.03 points de pourcentage à eps 0.10 et de 42.03 points à eps 0.15. La limite est que le PGD white-box à budget élevé reste très fort, donc le modèle neuronal seul ne doit pas être le modèle final déployé.

## Slide 8 - The Final Ensemble Breaks Transferability

Cette slide est le résultat de défense le plus fort. L'attaque transfer-PGD est générée contre le modèle Torch, qui joue le rôle de modèle surrogate. Ensuite, les mêmes exemples adversariaux sont testés contre l'ensemble final Adv+ExtraTrees.

Sur le modèle Torch, l'évasion est élevée: 37.29%, 63.99%, 91.24% et 100.00% selon la valeur de eps. Mais sur l'ensemble final, l'évasion devient 0.50%, 0.00%, 0.00% et 0.00%. Cela signifie que les exemples qui trompent le modèle neuronal ne se transfèrent presque pas vers le modèle final.

La déduction est que l'hétérogénéité de l'ensemble aide beaucoup. L'attaquant optimise les gradients du réseau neuronal, mais le modèle final contient une composante ExtraTrees robuste avec une structure de décision différente. Cette différence casse la transférabilité dans les attaques testées.

## Slide 9 - Security-OR Is Optional, Not The Main Claim

Security-OR est un mode de décision plus strict. Il signale une attaque si l'une des composantes calibrées est suffisamment confiante. Ce mode obtient 0.00% d'évasion transfer-PGD dans les résultats corrigés, donc il peut être utile dans un contexte très sensible.

Cependant, ce n'est pas le modèle par défaut car son F1 propre est plus faible. Security-OR obtient 0.8796 de F1, alors que Adv+ExtraTrees obtient 0.9063. Dans un déploiement réel, Security-OR serait intéressant si les faux négatifs coûtent beaucoup plus cher que des alertes supplémentaires.

Les limites doivent être dites clairement. NSL-KDD est un dataset ancien, les attaques en espace de features ne reproduisent pas parfaitement le trafic réel, R2L et U2R restent difficiles, et la robustesse observée est empirique, pas certifiée.

## Slide 10 - What This Project Demonstrates

Pour conclure, ce projet montre un pipeline CUDA reproductible pour un IDS explicable et testé contre des attaques adversariales. Nous avons entraîné plusieurs modèles, sélectionné Adv+ExtraTrees comme meilleur modèle par défaut, expliqué les décisions, mesuré la stabilité, attaqué les modèles, puis évalué les défenses.

Le modèle final obtient un F1 binaire de 0.9063, un PR-AUC de 0.9626, une balanced accuracy de 0.9064 et une stabilité locale d'explication de 0.845. Il réduit aussi l'évasion transfer-PGD testée presque à zéro.

Le message final est que l'explicabilité est nécessaire pour la confiance des analystes, mais en cybersécurité elle doit aussi être considérée comme une surface d'attaque potentielle. Un bon IDS explicable doit donc être performant, interprétable, stable et testé sous pression adversariale.
