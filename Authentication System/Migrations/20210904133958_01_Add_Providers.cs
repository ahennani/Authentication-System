using Microsoft.EntityFrameworkCore.Migrations;

namespace Authentication_System.Migrations
{
    public partial class _01_Add_Providers : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Provider",
                table: "Users");

            migrationBuilder.CreateTable(
                name: "Provider",
                columns: table => new
                {
                    ProviderId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: true),
                    UserId = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Provider", x => x.ProviderId);
                    table.ForeignKey(
                        name: "FK_Provider_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "UserId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Provider_Name",
                table: "Provider",
                column: "Name",
                unique: true,
                filter: "[Name] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_Provider_UserId",
                table: "Provider",
                column: "UserId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Provider");

            migrationBuilder.AddColumn<string>(
                name: "Provider",
                table: "Users",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: true);
        }
    }
}
