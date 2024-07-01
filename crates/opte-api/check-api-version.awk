BEGIN {
    old_vsn = 0;
    new_vsn = 0;
}

/^-pub const API_VERSION: u64 = [0-9]+/ {
    old_vsn = ($6 + 0);
}

/^\+pub const API_VERSION: u64 = [0-9]+/ {
    new_vsn = ($6 + 0);
}

END {
    if (new_vsn <= old_vsn) {
	printf("FAILURE: The API_VERSION was not updated\n");
	printf("\told: %u\n", old_vsn);
	printf("\tnew: %u\n", new_vsn);
	exit 1;
    }

    printf("SUCCESS: The API_VERSION was updated\n");
    printf("\told: %u\n", old_vsn);
    printf("\tnew: %u\n", new_vsn);
}
