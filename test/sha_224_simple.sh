arg=${1}
echo -n "${arg}" | ./ft_ssl sha224 -q 2> /dev/null > mine
echo -n "${arg}" | openssl sha224  2> /dev/null | ruby -e 'puts gets.split[-1]' > ref
diff mine ref
