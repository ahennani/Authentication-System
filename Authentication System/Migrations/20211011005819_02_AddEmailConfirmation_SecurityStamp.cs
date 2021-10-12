using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Authentication_System.Migrations
{
    public partial class _02_AddEmailConfirmation_SecurityStamp : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Mobile",
                table: "Users",
                newName: "MobilePhone");

            migrationBuilder.AddColumn<bool>(
                name: "EmailConfirmed",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<Guid>(
                name: "SecurityStamp",
                table: "Users",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EmailConfirmed",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "SecurityStamp",
                table: "Users");

            migrationBuilder.RenameColumn(
                name: "MobilePhone",
                table: "Users",
                newName: "Mobile");
        }
    }
}
