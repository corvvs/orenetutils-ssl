# HMAC: Hash-based Message Authentication Code

## 概要

メッセージ認証符号(MAC)の一種で, ハッシュアルゴリズムを基盤としたもの。

メッセージ認証符号とは, 与えたデータの変化を検出するための符号。

## より具体的な概要

HMAC自体は具体的なハッシュアルゴリズムに依存しないが, 使用するハッシュアルゴリズムを定めることで処理が定まる.

ハッシュアルゴリズムが決まっているとすると, HMAC処理は

- 2つの入力を取り
- 1つの値(=MAC)を出力する

関数として表される。

ここで2つの入力とは

- 秘密鍵(認証鍵)
- データ; 任意長であることが望ましい

である。

## アルゴリズム

cf. https://ja.wikipedia.org/wiki/HMAC \
cf. https://datatracker.ietf.org/doc/html/rfc2104 \
cf. https://www.nic.ad.jp/ja/tech/ipa/RFC2104JA.html

### 記号の定義

- `H`: 指定したハッシュアルゴリズムを実行する関数
    - ただし`H`はブロックアルゴリズムであるとする
- `B`: `H`のブロックバイトサイズ
- `L`: `H`の出力バイトサイズ
- `K`: 認証鍵
- `K'`: 短縮済み認証鍵
    - `K`のバイトサイズが`B`を超えている場合は`H(K)`
    - そうでない場合は単に`K`
- `text`: メッセージ
- `ipad`: インナーパディング; 64バイトの固定文字列; `0x3636...3636`
    - `0x36 = 0b00110110`
- `opad`: アウターパディング; 64バイトの固定文字列; `0x5c5c...5c5c`
    - `0x5c = 0b01011100`

### 処理内容

入力`K`, `text`に対するHMACは

```
H((K' ^ opad) +  H((K' ^ ipad) +  text))
```

で与えられる.\
ただし`+`はバイト列の連結, `^`はビットワイズXOR.




