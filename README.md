# RSA
###  Data: 23.06.2022r.
### Kierunek studiów: Teleinformatyka                           
### Przedmiot: Bezpieczeństwo systemów teleinformatycznych
### Autor: Krzysztof Jerzyk
### Numer indeksu: 143328

#### Generowanie kluczy wykorzystuje bibliotekę Cryptodome oraz autorkie funkcje. Liczby otrzymywane na wyjściu generatora są konwertowane z liczb calkowitych na liczby binarne przy pomocy funkcji ```get_random_bytes``` i podawane są jako argument funkcji ```generate```, która wtorzy x bitowe ciągi liczb. Funkcja poszukuje "duże" liczby pierwsze, na podstawie których generowane są klucze - prywatny i publiczny.
