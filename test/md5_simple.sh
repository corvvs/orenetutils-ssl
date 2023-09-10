arg=${1}
echo -n "${arg}" | ./ft_ssl md5 -q 2> /dev/null > mine
echo -n "${arg}" | openssl md5  2> /dev/null | ruby -e 'puts gets.split[-1]' > ref
diff mine ref
